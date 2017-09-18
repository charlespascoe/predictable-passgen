import { HashAlgorithm, Hbprng } from 'hbprng';

export class PasswordGenerator {
  private hbprng: Hbprng;

  constructor (
    private secret: Buffer,
    private hashAlg: HashAlgorithm = 'sha256',
    private alphabet: string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  ) { }

  public nextPassword(prevPass: string, length = 10): string {
    if (length < 8) {
      throw new Error('length must be at least 8');
    }

    let prevPassBuffer = Buffer.from(prevPass, 'utf8');

    let hbprng = new Hbprng(Buffer.concat([this.secret, prevPassBuffer]), this.hashAlg);

    let newPass = '';

    for (let i = 0; i < length; i++) {
      newPass += this.alphabet.charAt(hbprng.nextInt() % this.alphabet.length);
    }

    return newPass;
  }
}
