import org.hyperledger.fabric.contract.execution.JSONTransactionSerializer;
import org.hyperledger.fabric.contract.metadata.TypeSchema;

public class FuzzFromBuffer {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            JSONTransactionSerializer serializer = new JSONTransactionSerializer();
            TypeSchema ts = new TypeSchema();
            serializer.fromBuffer(data, ts);
        } catch (org.hyperledger.fabric.contract.ContractRuntimeException e) {
            // Expected exception, discard it
        }
    }
}