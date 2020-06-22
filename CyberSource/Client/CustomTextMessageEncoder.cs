
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.

using System;
using System.IO;
using System.ServiceModel.Channels;
using System.Xml;
using System.Xml.XPath;

namespace CyberSource.Clients
{
    public class CustomTextMessageEncoder : MessageEncoder
    {
        private CustomTextMessageEncoderFactory factory;
        private XmlWriterSettings writerSettings;
        private string contentType;
        private byte[] key;
   
        public CustomTextMessageEncoder(CustomTextMessageEncoderFactory factory)
        {
            this.factory = factory;
            
            this.writerSettings = new XmlWriterSettings();            
        }

        public override string ContentType
        {
            get
            {
                return "text/xml";
            }
        }

        public override string MediaType
        {
            get 
            {
                return "text/xml";
            }
        }

        public override MessageVersion MessageVersion
        {
            get 
            {
                return this.factory.MessageVersion;
            }
        }

        public override Message ReadMessage(ArraySegment<byte> buffer, BufferManager bufferManager, string contentType)
        {   
            bufferManager.ReturnBuffer(buffer.Array);

            using (MemoryStream stream = new MemoryStream(buffer.Array, buffer.Offset, buffer.Count))
            {
                return ReadMessage(stream, int.MaxValue);
            }
        }

        public override Message ReadMessage(Stream stream, int maxSizeOfHeaders, string contentType)
        {
            // Fix for Xml external entity injection violation in fortify report
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;

            XmlDocument doc = new XmlDocument();
            using (XmlReader reader = XmlReader.Create(stream, settings))
            {
                doc.Load(reader);
            }

            //We need to get rid of the security header because it is not signed by the web service.
            //The whole reason for the custom Encoder is to do this. the client rejected the unsigned header.
            //Our WCF client is set up to allow the absence of a security header but if the header exists then it must be signed.
            //Hopefully the namespace will not change. Maybe it should be put in a config.
            XPathNavigator n = doc.CreateNavigator();
            if (n.MoveToFollowing("Security", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"))
            {
                n.DeleteSelf();
            }

            return Message.CreateMessage(new XmlNodeReader(doc), maxSizeOfHeaders, MessageVersion.Soap11);
        }

        public override ArraySegment<byte> WriteMessage(Message message, int maxMessageSize, BufferManager bufferManager, int messageOffset)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                WriteMessage(message, stream);

                int messageLength = (int)stream.Position;
                int totalLength = messageLength + messageOffset;

                byte[] totalBytes = bufferManager.TakeBuffer(totalLength);

                byte[] messageBytes = stream.GetBuffer();

                Array.Copy(messageBytes, 0, totalBytes, messageOffset, messageLength);

                return new ArraySegment<byte>(totalBytes, messageOffset, messageLength);
            }
        }

        public override void WriteMessage(Message message, Stream stream)
        {
            using (XmlWriter writer = XmlWriter.Create(stream, this.writerSettings))
            {
                message.WriteMessage(writer);
                writer.Flush();
            }
        }
    }
}
