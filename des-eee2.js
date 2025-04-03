const CryptoJS = require("crypto-js");

// DES-EEE2 реализация с использованием crypto-js (для DES)
class DESEEE2 {
  constructor(key1, key2) {
    this.key1 = CryptoJS.enc.Utf8.parse(key1);
    this.key2 = CryptoJS.enc.Utf8.parse(key2);
    this.iv = CryptoJS.enc.Utf8.parse("12345678"); // IV для CBC режима
  }

  // Дополнение блока до нужного размера (PKCS7)
  padData(data) {
    const blockSize = 8; // DES block size is 8 bytes
    const padLength = blockSize - (data.length % blockSize);
    const paddedData = data + String.fromCharCode(padLength).repeat(padLength);
    return paddedData;
  }

  // Удаление дополнения
  unpadData(paddedData) {
    const padLength = paddedData.charCodeAt(paddedData.length - 1);
    return paddedData.slice(0, -padLength);
  }

  // Шифрование DES-EEE2
  encrypt(plaintext) {
    // Шаг 1: Первое шифрование DES с key1
    const encrypted1 = CryptoJS.DES.encrypt(
      CryptoJS.enc.Utf8.parse(plaintext),
      this.key1,
      { iv: this.iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    ).toString();

    // Шаг 2: Второе шифрование DES с key2
    const encrypted2 = CryptoJS.DES.encrypt(
      CryptoJS.enc.Base64.parse(encrypted1),
      this.key2,
      { iv: this.iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    ).toString();

    // Шаг 3: Третье шифрование DES с key1
    const encrypted3 = CryptoJS.DES.encrypt(
      CryptoJS.enc.Base64.parse(encrypted2),
      this.key1,
      { iv: this.iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    ).toString();

    return encrypted3;
  }

  // Дешифрование DES-EEE2
  decrypt(ciphertext) {
    // Шаг 1: Первое расшифрование DES с key1
    const decrypted1 = CryptoJS.DES.decrypt(ciphertext, this.key1, {
      iv: this.iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }).toString(CryptoJS.enc.Base64);

    // Шаг 2: Второе расшифрование DES с key2
    const decrypted2 = CryptoJS.DES.decrypt(decrypted1, this.key2, {
      iv: this.iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }).toString(CryptoJS.enc.Base64);

    // Шаг 3: Третье расшифрование DES с key1
    const decrypted3 = CryptoJS.DES.decrypt(decrypted2, this.key1, {
      iv: this.iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }).toString(CryptoJS.enc.Utf8);

    return decrypted3;
  }

  // Анализ лавинного эффекта
  avalancheEffect(plaintext, changedPlaintext) {
    const originalCipher = this.encrypt(plaintext);
    const changedCipher = this.encrypt(changedPlaintext);

    // Преобразуем в бинарные строки для сравнения
    const originalBinary = CryptoJS.enc.Base64.parse(originalCipher).toString(
      CryptoJS.enc.Hex
    );
    const changedBinary = CryptoJS.enc.Base64.parse(changedCipher).toString(
      CryptoJS.enc.Hex
    );

    // Считаем количество отличающихся битов
    let diffBits = 0;
    for (let i = 0; i < originalBinary.length; i++) {
      if (originalBinary[i] !== changedBinary[i]) {
        // Сравниваем каждый символ (каждый представляет 4 бита)
        const originalBits = parseInt(originalBinary[i], 16)
          .toString(2)
          .padStart(4, "0");
        const changedBits = parseInt(changedBinary[i], 16)
          .toString(2)
          .padStart(4, "0");

        for (let j = 0; j < 4; j++) {
          if (originalBits[j] !== changedBits[j]) {
            diffBits++;
          }
        }
      }
    }

    return {
      originalCipher: originalCipher,
      changedCipher: changedCipher,
      diffBits: diffBits,
      diffPercentage: (diffBits / (originalBinary.length * 4)) * 100,
    };
  }
}

module.exports = DESEEE2;
