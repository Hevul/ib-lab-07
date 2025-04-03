const { performance } = require("perf_hooks");
const CryptoJS = require("crypto-js");
const DESEEE2 = require("./des-eee2");

// Тестирование производительности
function testPerformance(desEEE2, testData, iterations = 1000) {
  // Тест шифрования
  const encryptStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    desEEE2.encrypt(testData);
  }
  const encryptEnd = performance.now();
  const encryptTime = encryptEnd - encryptStart;
  const encryptSpeed = (iterations / encryptTime) * 1000; // операций в секунду

  // Тест дешифрования
  const ciphertext = desEEE2.encrypt(testData);
  const decryptStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    desEEE2.decrypt(ciphertext);
  }
  const decryptEnd = performance.now();
  const decryptTime = decryptEnd - decryptStart;
  const decryptSpeed = (iterations / decryptTime) * 1000; // операций в секунду

  return {
    encryptTimePerOp: encryptTime / iterations,
    encryptSpeed: encryptSpeed,
    decryptTimePerOp: decryptTime / iterations,
    decryptSpeed: decryptSpeed,
  };
}

// Основная функция демонстрации
function main() {
  // Ключи для DES-EEE2 (2 разных ключа по 8 байт каждый)
  const key1 = "mykey123";
  const key2 = "secretk2";

  // Создаем экземпляр DES-EEE2
  const desEEE2 = new DESEEE2(key1, key2);

  // Тестовые данные
  const plaintext =
    "This is a secret message that needs to be encrypted using DES-EEE2!";
  console.log("Original plaintext:", plaintext);

  // Шифрование
  const ciphertext = desEEE2.encrypt(plaintext);
  console.log("\nEncrypted (DES-EEE2):", ciphertext);

  // Дешифрование
  const decrypted = desEEE2.decrypt(ciphertext);
  console.log("\nDecrypted:", decrypted);

  // Проверка корректности
  console.log("\nDecryption correct:", plaintext === decrypted);

  // Тестирование производительности
  const perfResults = testPerformance(desEEE2, plaintext);
  console.log("\nPerformance Results:");
  console.log(
    `Encryption: ${perfResults.encryptSpeed.toFixed(
      2
    )} ops/sec (${perfResults.encryptTimePerOp.toFixed(4)} ms/op)`
  );
  console.log(
    `Decryption: ${perfResults.decryptSpeed.toFixed(
      2
    )} ops/sec (${perfResults.decryptTimePerOp.toFixed(4)} ms/op)`
  );

  // Анализ лавинного эффекта
  const changedPlaintext = plaintext.replace("a", "A"); // Меняем один символ
  console.log("\nAvalanche Effect Analysis:");
  console.log("Original plaintext:", plaintext);
  console.log("Changed plaintext:", changedPlaintext);

  const avalancheResults = desEEE2.avalancheEffect(plaintext, changedPlaintext);
  console.log("\nOriginal ciphertext:", avalancheResults.originalCipher);
  console.log("Changed ciphertext:", avalancheResults.changedCipher);
  console.log(
    `\nDifferent bits: ${
      avalancheResults.diffBits
    } (${avalancheResults.diffPercentage.toFixed(2)}% of total bits)`
  );
}

// Запуск основной функции
main();
