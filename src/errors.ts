import BufferList from 'bl'

export class FailedIKError extends Error {
  public initialMsg: string|BufferList|Uint8Array

  constructor (initialMsg: string|BufferList|Uint8Array, message?: string) {
    super(message)

    this.initialMsg = initialMsg
    this.name = 'FailedIKhandshake'
  }
}
