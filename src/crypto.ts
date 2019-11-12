import { Duplex } from "./types/libp2p";
import { NoiseSession } from "./xx";

// Send encrypted payload from the user to stream
export async function encryptStreams(streams: Duplex, session: NoiseSession) : Promise<void> {

}


// Decrypt received payload from the stream and pipe to user
export async function decryptStreams(streams: Duplex, session: NoiseSession) : Promise<void> {

}
