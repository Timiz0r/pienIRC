use bytes::{Buf, BytesMut};
use pienirc::Message;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt, BufWriter},
    net::TcpStream,
};

pub struct Transport {
    stream: BufWriter<TcpStream>,
    read_buffer: BytesMut,
}

impl pienirc::Transport for Transport {
    async fn send(&mut self, message: Message) -> io::Result<()> {
        let bytes = match message.to_bytes() {
            Ok(bytes) => bytes,
            Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidInput, err)),
        };

        self.stream.write_all(&bytes[..]).await?;
        self.stream.flush().await?;

        Ok(())
    }

    async fn receive(&mut self) -> io::Result<Option<Message>> {
        loop {
            if let Ok(Some((message, size))) = Message::parse(&self.read_buffer) {
                self.read_buffer.advance(size);
                return Ok(Some(message));
            } else if self.stream.read_buf(&mut self.read_buffer).await? == 0 {
                if self.read_buffer.is_empty() {
                    // data completely read
                    return Ok(None);
                } else {
                    return Err(io::ErrorKind::ConnectionReset.into());
                }
            }
        }
    }
}
