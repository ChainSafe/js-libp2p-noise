import { x25519, HKDF, SHA256 } from 'bcrypto';
import protobuf from "protobufjs";
import { Buffer } from "buffer";
import PeerId from "peer-id";
import * as crypto from 'libp2p-crypto';
import { KeyPair } from "./@types/libp2p";
import {bytes, bytes32} from "./@types/basic";
import {Hkdf} from "./@types/handshake";
import payloadProto from "./proto/payload.json";

export async function loadPayloadProto () {
  const payloadProtoBuf = await protobuf.Root.fromJSON(payloadProto);
  return payloadProtoBuf.lookupType("NoiseHandshakePayload");
}

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
  const NoiseHandshakePayload = await loadPayloadProto();
  const earlyDataPayload = earlyData ?
    {
      data: earlyData,
    } : {};

  const payloadInit = NoiseHandshakePayload.create({
    identityKey: libp2pPublicKey,
    identitySig: signedPayload,
    ...earlyDataPayload,
  });

  return Buffer.from(NoiseHandshakePayload.encode(payloadInit).finish());
}


export async function signPayload(peerId: PeerId, payload: bytes): Promise<bytes> {
  return peerId.privKey.sign(payload);
}

export const getHandshakePayload = (publicKey: bytes ) => Buffer.concat([Buffer.from("noise-libp2p-static-key:"), publicKey]);

async function isValidPeerId(peerId: bytes, publicKeyProtobuf: bytes) {
  const generatedPeerId = await PeerId.createFromPubKey(publicKeyProtobuf);
  return generatedPeerId.id.equals(peerId);
}

export async function getPeerIdFromPayload(payload: bytes) {
  const decodedPayload = await decodePayload(payload);
  return await PeerId.createFromPubKey(decodedPayload.identityKey);
}

async function decodePayload(payload: bytes){
  const NoiseHandshakePayload = await loadPayloadProto();
  return NoiseHandshakePayload.toObject(
    NoiseHandshakePayload.decode(payload)
  );
}

export async function verifySignedPayload(noiseStaticKey: bytes, plaintext: bytes, peerId: bytes) {
  let receivedPayload;
  try {
    receivedPayload = await decodePayload(plaintext);
    //temporary fix until protobufsjs conversion options starts working
    //by default it ends up as Uint8Array
    receivedPayload.identityKey = Buffer.from(receivedPayload.identityKey);
    receivedPayload.identitySig = Buffer.from(receivedPayload.identitySig);
  } catch (e) {
    throw new Error("Failed to decode received payload. Reason: " + e.message);
  }

  if (!(await isValidPeerId(peerId, receivedPayload.identityKey)) ) {
    throw new Error("Peer ID doesn't match libp2p public key.");
  }

  const generatedPayload = getHandshakePayload(noiseStaticKey);

  // Unmarshaling from PublicKey protobuf
  const publicKey = crypto.keys.unmarshalPublicKey(receivedPayload.identityKey);
  if (!publicKey.verify(generatedPayload, receivedPayload.identitySig)) {
    throw new Error("Static key doesn't match to peer that signed payload!");
  }
}

export function getHkdf(ck: bytes32, ikm: bytes): Hkdf {
  const info = Buffer.alloc(0);
  const prk = HKDF.extract(SHA256, ikm, ck);
  const okm = HKDF.expand(SHA256, prk, info, 96);

  const k1 = okm.slice(0, 32);
  const k2 = okm.slice(32, 64);
  const k3 = okm.slice(64, 96);

  return [ k1, k2, k3 ];
}

export function isValidPublicKey(pk: bytes): boolean {
  return x25519.publicKeyVerify(pk);
}
