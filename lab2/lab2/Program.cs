using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace lab2
{
    class Program
    {
        private static uint P { get; set; }
        private static uint Q { get; set; }
        private static BigInteger N { get; set; }
        private static uint T { get; set; }
        private static uint E { get; set; }
        private static uint D { get; set; }

        private static void Main()
        {
            Console.Write("Textul pentru criptare: ");
            var textToEncrypt = Console.ReadLine();

            BigInteger message = TransformTextToBigInteger(textToEncrypt);

            List<uint> primeNumbers = GenerateFirstNPrimeNumbers(100);

            P = primeNumbers[GetRandomNumber(primeNumbers.Count - 1)];
            Q = primeNumbers[GetRandomNumber(primeNumbers.Count - 1)];
            N = P * Q;
            T = (P - 1) * (Q - 1);

            var eOptionsList = primeNumbers
                .Where(p => p < T)
                .Where(s => GCD(s, T) == 1)
                .ToList();

            E = eOptionsList[GetRandomNumber(eOptionsList.Count - 1)];

            AssignD();

            var encryptedString = "";
            var decryptedString = "";

            foreach (var t in message.ToString()) encryptedString += BigInteger.ModPow(int.Parse(t.ToString()), E, N) + " ";

            var dividedString = encryptedString.Split(' ').Where(s => !string.IsNullOrWhiteSpace(s)).ToList();

            dividedString.ForEach(e => decryptedString += BigInteger.ModPow(int.Parse(e), D, N));

            Console.WriteLine(
                "-----------------------------------------------------------------\n" +
                $"P: {P}\n" +
                $"Q: {Q}\n" +
                $"N: {N}\n" +
                $"T: {T}\n" +
                $"E: {E}\n" +
                $"D: {D}\n" +
                $"key publica: ({E}, {N})\n" +
                $"Key privata: ({D}, {N})\n" +
                "-----------------------------------------------------------------\n" +
                $"Criptat: {encryptedString}\n" +
                $"Decriptat: {Encoding.ASCII.GetString(BigInteger.Parse(decryptedString).ToByteArray())}"
            );
        }

        private static BigInteger TransformTextToBigInteger(string text) => new BigInteger(Encoding.ASCII.GetBytes(text));

        private static bool IsPrime(uint n)
        {
            for (uint i = 2; i <= n / 2; i++)
            {
                if (n % i == 0) return false;
            }

            return true;
        }

        private static List<uint> GenerateFirstNPrimeNumbers(uint n)
        {
            var result = new List<uint>();

            uint i = 2;

            while (result.Count < n)
            {
                if (IsPrime(i)) result.Add(i);

                i = i == 2 ? i + 1 : i + 2;
            }

            return result;
        }

        private static int GetRandomNumber(int max) => new Random().Next(max);

        static uint GCD(uint a, uint b) => b == 0 ? a : GCD(b, a % b);
        private static void AssignD()
        {
            var rand = 1;

            while (true)
            {
                var d = (decimal)(1 + rand * T) / E;

                if (d % 1 == 0)
                {
                    D = (uint)d;
                    break;
                }

                rand++;
            }
        }
    }
}
