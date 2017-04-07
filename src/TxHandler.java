import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class TxHandler {

    private final UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        if (null == tx)
            return false;

        List<UTXO> usedUTXO = new ArrayList<>();
        double sumInput = 0;
        double sumOutput = 0;

        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

            if (!(utxoPool.contains(utxo)) || usedUTXO.contains(utxo))
                return false;

            usedUTXO.add(utxo);

            Transaction.Output output = utxoPool.getTxOutput(utxo);
            PublicKey publicKey = output.address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = input.signature;

            if (!Crypto.verifySignature(publicKey, message, signature))
                return false;

            sumInput += output.value;
        }

        for (int i = 0; i < tx.numOutputs(); i++) {
            Transaction.Output output = tx.getOutput(i);
            if (output.value < 0)
                return false;

            sumOutput += output.value;
        }

        if (sumInput < sumOutput)
            return false;

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {

        if (null == possibleTxs)
            return null;

        List<Transaction> validTxs = new ArrayList<>();

        for(Transaction tx : possibleTxs) {
            if (isValidTx(tx)) {

                for (Transaction.Input input : tx.getInputs()) {
                    utxoPool.removeUTXO(new UTXO(input.prevTxHash, input.outputIndex));
                }

                int index = 0;
                byte[] txHash = tx.getHash();
                for (Transaction.Output output: tx.getOutputs()) {
                    utxoPool.addUTXO(new UTXO(txHash, index++),output);
                }

                validTxs.add(tx);
            }
        }

        return validTxs.toArray(new Transaction[validTxs.size()]);
    }

}
