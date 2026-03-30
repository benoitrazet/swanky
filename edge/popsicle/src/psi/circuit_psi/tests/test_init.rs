//! Testing the initialization phase in Base Psi
#[cfg(test)]
mod tests {

    use crate::psi::circuit_psi::{
        base_psi::{BasePsi, receiver::OpprfReceiver, sender::OpprfSender},
        tests::*,
    };
    use swanky_rng::AesRng;

    #[test]
    fn test_psty_init_receiver_succeeded() {
        for _ in 0..TEST_TRIALS {
            let (_, receiver) = swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut rng = AesRng::new();
                    let _ = OpprfSender::init(channel, &mut rng, true);
                    Ok(())
                },
                |channel| {
                    let mut rng = AesRng::new();
                    let receiver = OpprfReceiver::init(channel, &mut rng, true);
                    Ok(receiver)
                },
            )
            .unwrap();

            assert!(
                receiver.is_ok(),
                "PSTY Initialization failed on the receiver side"
            );
        }
    }
    #[test]
    fn test_psty_init_sender_succeeded() {
        for _ in 0..TEST_TRIALS {
            let (sender, _) = swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut rng = AesRng::new();
                    Ok(OpprfSender::init(channel, &mut rng, true))
                },
                |channel| {
                    let mut rng = AesRng::new();
                    let _ = OpprfReceiver::init(channel, &mut rng, true);
                    Ok(())
                },
            )
            .unwrap();

            assert!(
                sender.is_ok(),
                "PSTY Initialization failed on the sender side"
            );
        }
    }
}
