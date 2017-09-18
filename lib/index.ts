import { HashAlgorithm, Hbprng } from 'hbprng';


export interface IPasswordGeneratorOptions {
  hashAlg?: HashAlgorithm;
  characterSets?: string[];
  nonReplacement?: boolean;
}


export class PasswordGenerator {
  private hbprng: Hbprng;
  private hashAlg: HashAlgorithm;
  private characterSets: string[];
  private nonReplacement: boolean;
  private maxLength: number = -1;

  constructor(private secret: Buffer, options: IPasswordGeneratorOptions = {}) {
    this.hashAlg = options.hashAlg || 'sha256';
    this.characterSets = options.characterSets || ['abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'];
    this.nonReplacement = typeof options.nonReplacement === 'boolean' ? options.nonReplacement : false;

    if (this.characterSets.length === 0) {
      throw new Error('At least one character set is required');
    }

    if (this.characterSets.some(charSet => charSet.length === 0)) {
      throw new Error('Character sets cannot be empty');
    }

    if (this.nonReplacement) {
      this.maxLength = this.characterSets.reduce((count, charSet) => charSet.length + count, 0);
    }
  }

  public genPassword(seed: Buffer, length = 10): string {
    if (length < this.characterSets.length) {
      throw new Error(`length must be at least ${this.characterSets.length}`);
    }

    if (this.nonReplacement && length > this.maxLength) {
      throw new Error(`length must not be longer than ${this.maxLength} with non-replacement option`);
    }

    let hbprng = new Hbprng(Buffer.concat([this.secret, seed]), this.hashAlg);

    let newPass = '';

    let charSets = this.characterSets.slice(0);

    for (let i = 0; i < length; i++) {
      let charSet = charSets[i % charSets.length];

      let charIndex = hbprng.nextInt() % charSet.length;

      newPass += charSet.charAt(charIndex);

      if (this.nonReplacement) {
        charSet = charSet.slice(0, charIndex) + charSet.slice(charIndex + 1);

        if (charSet.length === 0) {
          charSets.splice(i % charSets.length, 1);
        } else {
          charSets[i % charSets.length] = charSet;
        }
      }
    }

    return newPass;
  }
}
