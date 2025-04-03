const CryptoJS = require("crypto-js");

class DESEEE2 {
  constructor(key1, key2, useECB = false) {
    this.key1 = CryptoJS.enc.Utf8.parse(key1);
    this.key2 = CryptoJS.enc.Utf8.parse(key2);
    this.iv = CryptoJS.enc.Utf8.parse("12345678");
    this.useECB = useECB; // Флаг для использования ECB режима со слабыми ключами
  }

  // Шифрование DES-EEE2
  encrypt(plaintext) {
    const options = {
      mode: this.useECB ? CryptoJS.mode.ECB : CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
      iv: this.useECB ? undefined : this.iv
    };

    // Шаг 1: Первое шифрование DES с key1
    const encrypted1 = CryptoJS.DES.encrypt(
      CryptoJS.enc.Utf8.parse(plaintext),
      this.key1,
      options
    ).toString();

    // Шаг 2: Второе шифрование DES с key2
    const encrypted2 = CryptoJS.DES.encrypt(
      CryptoJS.enc.Base64.parse(encrypted1),
      this.key2,
      options
    ).toString();

    // Шаг 3: Третье шифрование DES с key1
    const encrypted3 = CryptoJS.DES.encrypt(
      CryptoJS.enc.Base64.parse(encrypted2),
      this.key1,
      options
    ).toString();

    return encrypted3;
  }

  // Дешифрование DES-EEE2
  decrypt(ciphertext) {
    const options = {
      mode: this.useECB ? CryptoJS.mode.ECB : CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
      iv: this.useECB ? undefined : this.iv
    };

    // Шаг 1: Первое расшифрование DES с key1
    const decrypted1 = CryptoJS.DES.decrypt(
      ciphertext,
      this.key1,
      options
    ).toString(CryptoJS.enc.Base64);

    // Шаг 2: Второе расшифрование DES с key2
    const decrypted2 = CryptoJS.DES.decrypt(
      decrypted1,
      this.key2,
      options
    ).toString(CryptoJS.enc.Base64);

    // Шаг 3: Третье расшифрование DES с key1
    const decrypted3 = CryptoJS.DES.decrypt(
      decrypted2,
      this.key1,
      options
    ).toString(CryptoJS.enc.Utf8);

    return decrypted3;
  }

  // Анализ лавинного эффекта
  avalancheEffect(plaintext, changedPlaintext) {
    const originalCipher = this.encrypt(plaintext);
    const changedCipher = this.encrypt(changedPlaintext);

    const originalBinary = CryptoJS.enc.Base64.parse(originalCipher).toString(CryptoJS.enc.Hex);
    const changedBinary = CryptoJS.enc.Base64.parse(changedCipher).toString(CryptoJS.enc.Hex);

    let diffBits = 0;
    for (let i = 0; i < originalBinary.length; i++) {
      if (originalBinary[i] !== changedBinary[i]) {
        const originalBits = parseInt(originalBinary[i], 16).toString(2).padStart(4, "0");
        const changedBits = parseInt(changedBinary[i], 16).toString(2).padStart(4, "0");

        for (let j = 0; j < 4; j++) {
          if (originalBits[j] !== changedBits[j]) diffBits++;
        }
      }
    }

    return {
      originalCipher: originalCipher,
      changedCipher: changedCipher,
      diffBits: diffBits,
      diffPercentage: (diffBits / (originalBinary.length * 4)) * 100
    };
  }
}

module.exports = DESEEE2;