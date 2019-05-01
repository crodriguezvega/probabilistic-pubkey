/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "could not generate public key")]
    CouldNotGeneratePublicKey,
}