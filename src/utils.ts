import {HKDF, SHA256, x25519} from 'bcrypto';
import {Buffer} from "buffer";
import PeerId from "peer-id";
import * as crypto from 'libp2p-crypto';
import {KeyPair} from "./@types/libp2p";
import {bytes, bytes32} from "./@types/basic";
import {Hkdf, INoisePayload} from "./@types/handshake";
import {pb} from "./proto/payload";

const NoiseHandshakePayloadProto = pb.NoiseHandshakePayload;

export function generateKeypair(): KeyPair {
  const privateKey = x25519.privateKeyGenerate();
  const publicKey = x25519.publicKeyCreate(privateKey);

  return {
    publicKey,
    privateKey,
  }
}

export async function getPayload(
  localPeer: PeerId,
  staticPublicKey: bytes,
  earlyData?: bytes,
): Promise<bytes> {
  const signedPayload = await signPayload(localPeer, getHandshakePayload(staticPublicKey));
  const earlyDataPayload = earlyData || Buffer.alloc(0);

  return await createHandshakePayload(
    localPeer.marshalPubKey(),
    signedPayload,
    earlyDataPayload
  );
}

export async function createHandshakePayload(
  libp2pPublicKey: bytes,
  signedPayload: bytes,
  earlyData?: bytes,
): Promise<bytes> {

  const payloadInit = NoiseHandshakePayloadProto.create({
    identityKey: libp2pPublicKey,
    identitySig: signedPayload,
    data: earlyData || null,
  });

  return Buffer.from(NoiseHandshakePayloadProto.encode(payloadInit).finish());
}


export async function signPayload(peerId: PeerId, payload: bytes): Promise<bytes> {
  return peerId.privKey.sign(payload);
}

export async function getPeerIdFromPayload(payload: pb.INoiseHandshakePayload): Promise<PeerId> {
  return await PeerId.createFromPubKey(Buffer.from(payload.identityKey as Uint8Array));
}

export async function decodePayload(payload: bytes|Uint8Array): Promise<pb.INoiseHandshakePayload> {
  return NoiseHandshakePayloadProto.toObject(
    NoiseHandshakePayloadProto.decode(Buffer.from(payload))
  ) as INoisePayload;
}

export function getHandshakePayload(publicKey: bytes): bytes {
  return Buffer.concat([Buffer.from("noise-libp2p-static-key:"), publicKey]);
}

async function isValidPeerId(peerId: bytes, publicKeyProtobuf: bytes) {
  const generatedPeerId = await PeerId.createFromPubKey(publicKeyProtobuf);
  return generatedPeerId.id.equals(peerId);
}

/**
 * Verifies signed payload, throws on any irregularities.
 * @param {bytes} noiseStaticKey - owner's noise static key
 * @param {bytes} payload - decoded payload
 * @param {PeerId} remotePeer - owner's libp2p peer ID
 * @returns {Promise<PeerId>} - peer ID of payload owner
 */
export async function verifySignedPayload(
  noiseStaticKey: bytes,
  payload: pb.INoiseHandshakePayload,
  remotePeer: PeerId
): Promise<PeerId> {
  const identityKey = Buffer.from(payload.identityKey as Uint8Array);
  if (!(await isValidPeerId(remotePeer.id, identityKey))) {
    throw new Error("Peer ID doesn't match libp2p public key.");
  }
  const generatedPayload = getHandshakePayload(noiseStaticKey);
  // Unmarshaling from PublicKey protobuf
  const publicKey = crypto.keys.unmarshalPublicKey(identityKey);
  if (!publicKey.verify(generatedPayload, payload.identitySig)) {
    throw new Error("Static key doesn't match to peer that signed payload!");
  }
  return remotePeer;
}

export function getHkdf(ck: bytes32, ikm: bytes): Hkdf {
  const info = Buffer.alloc(0);
  const prk = HKDF.extract(SHA256, ikm, ck);
  const okm = HKDF.expand(SHA256, prk, info, 96);

  const k1 = okm.slice(0, 32);
  const k2 = okm.slice(32, 64);
  const k3 = okm.slice(64, 96);

  return [k1, k2, k3];
}

export function isValidPublicKey(pk: bytes): boolean {
  return x25519.publicKeyVerify(pk.slice(0, 32));
}
