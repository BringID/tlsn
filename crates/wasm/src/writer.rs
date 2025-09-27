use std::io::{self, Write};
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use std::sync::Arc;
use crossbeam_channel::{unbounded, Sender, Receiver};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

pub(crate) struct PostMessageWriter {
    tx: Arc<Sender<String>>,
}

impl PostMessageWriter {
    pub(crate) fn new(tx: Arc<Sender<String>>) -> Self {
        Self { tx }
    }
}


impl Write for PostMessageWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s = String::from_utf8_lossy(buf).to_string();
        let message = s.trim_end().to_string();

        if !message.is_empty() {
            let _ = self.tx.send(message);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// MakePostMessageWriter

pub(crate) struct MakePostMessageWriter {
    tx: Arc<Sender<String>>,
}

impl MakePostMessageWriter {
    pub(crate) fn new(tx: Arc<Sender<String>>) -> Self {
        Self { tx }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakePostMessageWriter {
    type Writer = PostMessageWriter;

    fn make_writer(&'a self) -> Self::Writer {
        PostMessageWriter::new(self.tx.clone())
    }
}