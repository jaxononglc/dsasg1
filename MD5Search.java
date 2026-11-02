import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * MD5Search - Multithreaded brute-force MD5 password cracker.
 *
 * Usage:
 *   java MD5Search <md5Hash> <numThreads> <passwordLength>
 *
 * Example:
 *   java MD5Search 32d3971fff9e081490c614319d63d594 4 4
 *
 * Partitioning strategy:
 *   The search space is every string of length `passwordLength` built from
 *   95 printable ASCII characters (decimal 32-126 inclusive... actually the
 *   assignment uses 33-126, 94 characters, matching Appendix A). The FIRST
 *   character of the candidate password is what gets split across threads.
 *   The 94 possible first characters are divided into N contiguous, non-
 *   overlapping ranges (as evenly as possible; any remainder is spread one
 *   extra character at a time across the first few threads). Each thread
 *   then independently brute-forces all remaining (passwordLength - 1)
 *   character positions for every first character in its assigned range,
 *   in deterministic lexicographic order (recursive candidate generation,
 *   always iterating the character set from CHAR_MIN to CHAR_MAX).
 *
 * Coordination:
 *   A shared AtomicBoolean `found` is checked by every thread at the start
 *   of each new candidate and at the top of every recursion level. As soon
 *   as one thread matches the target hash, it sets `found` to true and
 *   records the password + its own thread id in shared AtomicReference /
 *   volatile fields. Other threads observe the flag (at worst, after
 *   finishing their current partial branch) and return promptly. The main
 *   thread joins on every worker before computing/reporting the total
 *   elapsed time, satisfying the "wait for all threads to terminate before
 *   reporting execution time" requirement.
 */
public class MD5Search {

    // ASCII range used for candidate characters (matches Appendix A: 33-126 inclusive)
    private static final int CHAR_MIN = 33;
    private static final int CHAR_MAX = 126;
    private static final int CHARSET_SIZE = CHAR_MAX - CHAR_MIN + 1; // 94

    // Shared coordination state
    private static final AtomicBoolean found = new AtomicBoolean(false);
    private static final AtomicReference<String> foundPassword = new AtomicReference<>(null);
    private static volatile long foundByThreadId = -1;

    public static void main(String[] args) {

        // ---- 1. Input validation ----
        if (args.length != 3) {
            System.err.println("Error: expected 3 arguments.");
            System.err.println("Usage: java MD5Search <md5Hash> <numThreads> <passwordLength>");
            return;
        }

        String targetHash = args[0];
        int numThreads;
        int passwordLength;

        if (!isValidMd5Hash(targetHash)) {
            System.err.println("Error: '" + targetHash + "' is not a valid MD5 hash. " +
                    "It must be exactly 32 hexadecimal characters.");
            return;
        }
        targetHash = targetHash.toLowerCase();

        try {
            numThreads = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            System.err.println("Error: thread count must be an integer.");
            return;
        }
        if (numThreads < 1 || numThreads > 10) {
            System.err.println("Error: thread count must be between 1 and 10 (got " + numThreads + ").");
            return;
        }

        try {
            passwordLength = Integer.parseInt(args[2]);
        } catch (NumberFormatException e) {
            System.err.println("Error: password length must be an integer.");
            return;
        }
        if (passwordLength < 1) {
            System.err.println("Error: password length must be at least 1 (got " + passwordLength + ").");
            return;
        }

        // Don't create more threads than there are first characters to split
        int threadsToUse = Math.min(numThreads, CHARSET_SIZE);
        if (threadsToUse < numThreads) {
            System.out.println("Note: reducing threads from " + numThreads + " to " + threadsToUse +
                    " (cannot usefully split " + CHARSET_SIZE + " first-characters further).");
        }

        // ---- 2. Partition the search space across threads ----
        // Split CHARSET_SIZE (94) first-characters into threadsToUse contiguous ranges.
        int baseShare = CHARSET_SIZE / threadsToUse;
        int remainder = CHARSET_SIZE % threadsToUse;

        Thread[] workers = new Thread[threadsToUse];
        int rangeStart = CHAR_MIN;

        long startTime = System.currentTimeMillis();

        for (int t = 0; t < threadsToUse; t++) {
            // Give the first `remainder` threads one extra first-character to cover
            // the case where CHARSET_SIZE doesn't divide evenly.
            int share = baseShare + (t < remainder ? 1 : 0);
            int rangeEndExclusive = rangeStart + share; // [rangeStart, rangeEndExclusive)

            final int fromChar = rangeStart;
            final int toCharExclusive = rangeEndExclusive;
            final int threadId = t + 1;
            final String hashToMatch = targetHash;
            final int pwLen = passwordLength;

            workers[t] = new Thread(() -> {
                char[] candidate = new char[pwLen];
                for (int c = fromChar; c < toCharExclusive && !found.get(); c++) {
                    candidate[0] = (char) c;
                    search(candidate, 1, pwLen, hashToMatch, threadId);
                }
            }, "Worker-" + threadId);

            rangeStart = rangeEndExclusive;
        }

        // ---- 3. Start all threads ----
        for (Thread w : workers) {
            w.start();
        }

        // ---- 4. Wait for all threads to finish before reporting anything ----
        for (Thread w : workers) {
            try {
                w.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                System.err.println("Main thread interrupted while waiting for workers.");
            }
        }

        long endTime = System.currentTimeMillis();
        double elapsedSeconds = (endTime - startTime) / 1000.0;

        // ---- 5. Report results ----
        if (found.get()) {
            System.out.println("Password found: " + foundPassword.get());
            System.out.println("Found by thread: " + foundByThreadId);
        } else {
            System.out.println("Password not found in the search space " +
                    "(length " + passwordLength + ", charset 33-126).");
        }
        System.out.println("Threads used: " + threadsToUse);
        System.out.println("Total execution time: " + elapsedSeconds + " seconds");
    }

    /**
     * Recursively fills candidate[pos..length-1] in deterministic order
     * (CHAR_MIN to CHAR_MAX at every position) and tests each complete
     * candidate against the target hash. Bails out early, at every level,
     * if another thread has already found the password.
     */
    private static void search(char[] candidate, int pos, int length, String targetHash, int threadId) {
        if (found.get()) {
            return;
        }
        if (pos == length) {
            String attempt = new String(candidate);
            if (getMd5(attempt).equals(targetHash)) {
                // Only the first thread to succeed actually records the result;
                // compareAndSet guards against a rare simultaneous match.
                if (found.compareAndSet(false, true)) {
                    foundPassword.set(attempt);
                    foundByThreadId = threadId;
                }
            }
            return;
        }
        for (int c = CHAR_MIN; c <= CHAR_MAX; c++) {
            if (found.get()) {
                return;
            }
            candidate[pos] = (char) c;
            search(candidate, pos + 1, length, targetHash, threadId);
        }
    }

    /** Returns true if s is exactly 32 hexadecimal characters. */
    private static boolean isValidMd5Hash(String s) {
        if (s == null || s.length() != 32) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean isHexDigit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHexDigit) {
                return false;
            }
        }
        return true;
    }

    /** Computes the MD5 hash of the input string, returned as a lowercase 32-char hex string. */
    private static String getMd5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}