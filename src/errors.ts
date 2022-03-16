import type { Uint8ArrayList } from 'uint8arraylist'

export class FailedIKError extends Error {
  public initialMsg: string|Uint8ArrayList|Uint8Array

  constructor (initialMsg: string|Uint8ArrayList|Uint8Array, message?: string) {
    super(message)

    this.initialMsg = initialMsg
    this.name = 'FailedIKhandshake'
  }
}
