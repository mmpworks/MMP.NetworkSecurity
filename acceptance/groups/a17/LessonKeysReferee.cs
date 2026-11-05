using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17.referee.lesson-keys-openssl-mac (modes-design.md section 8.6, the my-lesson-keys row). On the learner's own lesson keys, OpenSSL recomputes what the labs
    /// computed: the CMAC and HMAC tags of lesson 2 over the lab's fixed message, and the first ECB block of lesson 1. The key bytes come from the key route,
    /// so a lab that ignored the learner's key gives a tag OpenSSL does not reproduce. A frame is a 4-byte header, then a body (FrameEngine.HeaderSize).
    /// </summary>
    public static class LessonKeysReferee
    {
        const int HeaderSize = 4, LengthPrefix = 2;

        static Dictionary<string, object> EventWithMessage(SessionRun run, string message)
        {
            foreach (Dictionary<string, object> ev in run.Events)
                if (MiniJson.Str(ev, "message") == message && !string.IsNullOrEmpty(MiniJson.Str(ev, "wire"))) return ev;
            throw new FailException("the trace holds no event for the message " + message + " with its wire bytes");
        }

        static string Openssl(string openssl, string dir, string args, out int code)
        {
            string o;
            code = Proc.Run(openssl, args, dir, 30000, out o);
            return o.Trim();
        }

        [Clause("A17.referee.lesson-keys-openssl-mac")]
        public static string LessonKeysOpensslMac(Ctx c)
        {
            string openssl = Referees.OpenSsl(c);
            using (HostProc h = A17.Host(c, "a17-lessonkeys-ref"))
            {
                A17.RunFlow(h, "my-lesson-keys", null);
                string aesHex = MiniJson.Str(A17.Key(h, "lab.aes-key").Json, "hex"), sealHex = MiniJson.Str(A17.Key(h, "lab.seal-key").Json, "hex");
                Check.True(!string.IsNullOrEmpty(aesHex) && !string.IsNullOrEmpty(sealHex), "the key route shows no bytes for lab.aes-key or lab.seal-key with Show keys ON");
                string dir = A17.TempDir(c, "lessonkeys");
                int code;

                // Lesson 2: the seals.
                SessionRun two = HostSession.Run(h, 2, "glass", null);
                if (two.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 2 as not built yet");
                Check.True(two.Error == null && two.Finished != null, "lesson 2 on the learner's seal key did not finish");
                string labKey = null;
                foreach (A17.SecretRef s in A17.Secrets(two)) if (s.Name == "seal.key" && s.Hex.Length > 0) labKey = s.Hex;
                Check.True(labKey != null && labKey.Equals(sealHex, StringComparison.OrdinalIgnoreCase), "lesson 2 holds the key " + labKey + ", not the learner's seal key " + sealHex);

                foreach (string kind in new string[] { "CmacSealed", "HmacSealed" })
                {
                    Dictionary<string, object> ev = EventWithMessage(two, kind);
                    byte[] wire = Hex.Decode(MiniJson.Str(ev, "wire")), message = Hex.Decode(MiniJson.Str(ev, "plain"));
                    int tagStart = HeaderSize + LengthPrefix + message.Length;
                    Check.True(wire.Length > tagStart, kind + ": the frame is " + wire.Length + " bytes; the message ends at " + tagStart);
                    byte[] labTag = Hex.Slice(wire, tagStart, wire.Length - tagStart);
                    string msgFile = Path.Combine(dir, kind + ".msg");
                    File.WriteAllBytes(msgFile, message);
                    string mac = kind == "CmacSealed"
                        ? Openssl(openssl, dir, "mac -cipher AES-128-CBC -macopt hexkey:" + sealHex + " -in \"" + msgFile + "\" CMAC", out code)
                        : Openssl(openssl, dir, "mac -digest SHA256 -macopt hexkey:" + sealHex + " -in \"" + msgFile + "\" HMAC", out code);
                    Check.True(code == 0, "openssl mac failed for " + kind + ": " + mac);
                    Check.Equal(kind + " tag, OpenSSL against the lab", mac.ToLowerInvariant(), Hex.Encode(labTag));
                    // Control: OpenSSL gives another tag over a changed message, so a match above is no accident.
                    byte[] changed = (byte[])message.Clone();
                    changed[0] ^= 0x01;
                    File.WriteAllBytes(msgFile, changed);
                    string other = kind == "CmacSealed"
                        ? Openssl(openssl, dir, "mac -cipher AES-128-CBC -macopt hexkey:" + sealHex + " -in \"" + msgFile + "\" CMAC", out code)
                        : Openssl(openssl, dir, "mac -digest SHA256 -macopt hexkey:" + sealHex + " -in \"" + msgFile + "\" HMAC", out code);
                    Check.True(other.ToLowerInvariant() != Hex.Encode(labTag), "control: OpenSSL gives the lab's " + kind + " tag over a changed message");
                }

                // Lesson 1: the first ECB block of the picture.
                SessionRun one = HostSession.Run(h, 1, "glass", null);
                if (one.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 1 as not built yet");
                Check.True(one.Error == null && one.Finished != null, "lesson 1 on the learner's AES key did not finish");
                string aesInTrace = null;
                foreach (A17.SecretRef s in A17.Secrets(one)) if (s.Name == "aes.key" && s.Hex.Length > 0) aesInTrace = s.Hex;
                Check.True(aesInTrace != null && aesInTrace.Equals(aesHex, StringComparison.OrdinalIgnoreCase), "lesson 1 holds the key " + aesInTrace + ", not the learner's AES key " + aesHex);
                Dictionary<string, object> ecb = EventWithMessage(one, "PictureEcb");
                byte[] ecbWire = Hex.Decode(MiniJson.Str(ecb, "wire")), picture = Hex.Decode(MiniJson.Str(ecb, "plain"));
                Check.True(picture.Length >= 16 && ecbWire.Length >= HeaderSize + 16, "the ECB frame is too short for a block");
                string block = Path.Combine(dir, "block.bin"), enc = Path.Combine(dir, "block.enc");
                File.WriteAllBytes(block, Hex.Slice(picture, 0, 16));
                Openssl(openssl, dir, "enc -aes-128-ecb -nopad -K " + aesHex + " -in \"" + block + "\" -out \"" + enc + "\"", out code);
                Check.True(code == 0, "openssl enc failed");
                Check.Bytes("first ECB block, OpenSSL against the lab", File.ReadAllBytes(enc), Hex.Slice(ecbWire, HeaderSize, 16));
                return "on the learner's lesson keys OpenSSL reproduces the lab's CMAC and HMAC tags of lesson 2 and the first ECB block of lesson 1, and gives other tags over a changed message";
            }
        }
    }
}
