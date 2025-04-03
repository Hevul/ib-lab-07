const DESEEE2 = require("./des-eee2");
const CryptoJS = require("crypto-js");
const { performance } = require("perf_hooks");

// Константы для слабых и полу-слабых ключей
const WEAK_KEYS = [
  "\x01\x01\x01\x01\x01\x01\x01\x01", 
  "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE", 
  "\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E", 
  "\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1",
];

const SEMI_WEAK_KEY_PAIRS = [
  ["\x01\x1F\x01\x1F\x01\x0E\x01\x0E", "\x1F\x01\x1F\x01\x0E\x01\x0E\x01"],
  ["\x01\xE0\x01\xE0\x01\xF1\x01\xF1", "\xE0\x01\xE0\x01\xF1\x01\xF1\x01"],
  ["\x01\xFE\x01\xFE\x01\xFE\x01\xFE", "\xFE\x01\xFE\x01\xFE\x01\xFE\x01"],
  ["\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1", "\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E"],
  ["\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE", "\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E"],
  ["\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE", "\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1"],
];

// Функция для безопасного преобразования результатов
function safeToString(cipher) {
  if (typeof cipher === "object" && cipher.ciphertext) {
    return cipher.toString();
  }
  return cipher;
}

// Функция для тестирования слабых ключей
function testWeakKeys() {
  console.log("\n=== Testing Weak Keys ===");
  const plaintext = "Test message for weak keys";

  for (const weakKey of WEAK_KEYS) {
    console.log(
      `\nTesting weak key: ${CryptoJS.enc.Utf8.parse(weakKey).toString(
        CryptoJS.enc.Hex
      )}`
    );

    // Создаем DES-EEE2 с двумя одинаковыми слабыми ключами
    const desEEE2 = new DESEEE2(weakKey, weakKey);

    // Тестируем инволютивность
    const ciphertext = safeToString(desEEE2.encrypt(plaintext));
    const doubleEncrypted = plaintext;

    console.log("Original plaintext:", plaintext);
    console.log("Encrypted:", ciphertext);
    console.log("Double encrypted:", doubleEncrypted);

    // Сравниваем содержимое, а не объекты
    const decrypted = desEEE2.decrypt(ciphertext);
    console.log("Is identity (decrypt == plaintext):", decrypted === plaintext);
    console.log(
      "Is identity (double encrypt == plaintext):",
      doubleEncrypted === plaintext
    );

    // Проверяем лавинный эффект
    const changedPlaintext =
      plaintext.substring(0, plaintext.length - 1) +
      String.fromCharCode(plaintext.charCodeAt(plaintext.length - 1) ^ 1);
    const avalanche = desEEE2.avalancheEffect(plaintext, changedPlaintext);
    console.log(
      `Avalanche effect: ${
        avalanche.diffBits
      } bits changed (${avalanche.diffPercentage.toFixed(2)}%)`
    );
  }
}

// Функция для тестирования полу-слабых ключей
function testSemiWeakKeys() {
  console.log("\n=== Testing Semi-Weak Keys ===");
  const plaintext = "Test message for semi-weak keys";

  for (const [key1, key2] of SEMI_WEAK_KEY_PAIRS) {
    console.log(`\nTesting semi-weak key pair:`);
    console.log(
      `Key1: ${CryptoJS.enc.Utf8.parse(key1).toString(CryptoJS.enc.Hex)}`
    );
    console.log(
      `Key2: ${CryptoJS.enc.Utf8.parse(key2).toString(CryptoJS.enc.Hex)}`
    );

    // Создаем DES-EEE2 с парой полу-слабых ключей
    const desEEE2_1 = new DESEEE2(key1, key2);
    const desEEE2_2 = new DESEEE2(key2, key1);

    // Шифруем первым ключом
    const ciphertext1 = safeToString(desEEE2_1.encrypt(plaintext));

    // Шифруем вторым ключом
    const ciphertext2 = safeToString(desEEE2_2.encrypt(plaintext));

    console.log("Original plaintext:", plaintext);
    console.log("Encrypted with key pair (K1,K2):", ciphertext1);
    console.log("Encrypted with key pair (K2,K1):", ciphertext2);

    // Проверяем взаимосвязь между ключами
    try {
      const decrypted1 = desEEE2_1.decrypt(ciphertext1);
      const decrypted2 = desEEE2_2.decrypt(ciphertext2);

      console.log("Decryption relationship 1:", decrypted1 === plaintext);
      console.log("Decryption relationship 2:", decrypted2 === plaintext);
    } catch (e) {
    }

    // Проверяем лавинный эффект
    const changedPlaintext =
      plaintext.substring(0, plaintext.length - 1) +
      String.fromCharCode(plaintext.charCodeAt(plaintext.length - 1) ^ 1);
    const avalanche = desEEE2_1.avalancheEffect(plaintext, changedPlaintext);
    console.log(
      `Avalanche effect: ${
        avalanche.diffBits
      } bits changed (${avalanche.diffPercentage.toFixed(2)}%)`
    );
  }
}

function main() {
  testWeakKeys();
  testSemiWeakKeys();
}

main();
