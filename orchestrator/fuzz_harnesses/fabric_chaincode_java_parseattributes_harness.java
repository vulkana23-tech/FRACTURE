import org.hyperledger.fabric.contract.ClientIdentity;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/* Harness real de Jazzer para ClientIdentity.parseAttributes()
 * (fabric-chaincode-java/fabric-chaincode-shim) -- toma
 * extensionValue: byte[] (DER-encoded ASN.1 octet string, extraido de
 * un extension OID especifico de un certificado X.509 real via
 * cert.getExtensionValue(FABRIC_CERT_ATTR_OID) en el constructor
 * real), lo parsea como ASN.1 (BouncyCastle) -> octet string -> UTF-8
 * -> JSON (org.json) -> itera "attrs" como mapa de key/value.
 *
 * Mismo patron real que YA encontro bugs en este proyecto en Go
 * (attrmgr.GetAttributesFromCert/GetAttributesFromIdemix,
 * fabric-chaincode-go) y C++ (unmarshal_values,
 * fabric-private-chaincode) -- Fabric implementa el mismo esquema de
 * "atributos de identidad codificados en JSON dentro de una extension
 * de certificado" en al menos 3 lenguajes distintos, cada uno con su
 * propio parseo independiente.
 *
 * parseAttributes() es un metodo PRIVADO de instancia -- se crea una
 * instancia de ClientIdentity SIN correr el constructor real (via
 * ReflectionFactory, tecnica estandar de Java para bypass de
 * constructor) porque el constructor real necesita un ChaincodeStub +
 * SignedIdentity + X509Certificate reales armados a mano, y
 * parseAttributes() no toca ningun campo de instancia (todos son
 * `private final` sin usar en el metodo, confirmado leyendo el codigo
 * real) -- crear la instancia asi es seguro.
 *
 * Reachability real: el constructor real de ClientIdentity llama
 * exactamente esta funcion sobre bytes de una extension de
 * certificado X.509 -- certificados los emite la MSP (Membership
 * Service Provider) de un canal Fabric, no necesariamente confiable
 * si esa MSP esta comprometida o mal configurada (mismo modelo de
 * amenaza ya documentado para los harnesses hermanos de Go/C++).
 */
public class FuzzParseAttributes {
    private static final Object INSTANCE;
    private static final Method PARSE_ATTRIBUTES;

    static {
        try {
            sun.reflect.ReflectionFactory rf = sun.reflect.ReflectionFactory.getReflectionFactory();
            Constructor<Object> objectCtor = Object.class.getDeclaredConstructor();
            Constructor<?> ctor = rf.newConstructorForSerialization(ClientIdentity.class, objectCtor);
            ctor.setAccessible(true);
            INSTANCE = ctor.newInstance();

            PARSE_ATTRIBUTES = ClientIdentity.class.getDeclaredMethod("parseAttributes", byte[].class);
            PARSE_ATTRIBUTES.setAccessible(true);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static void fuzzerTestOneInput(byte[] data) {
        try {
            PARSE_ATTRIBUTES.invoke(INSTANCE, (Object) data);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            // IOException/JSONException son el camino esperado para
            // bytes invalidos (ASN.1 mal formado, JSON mal formado) --
            // la propia funcion los declara/atrapa como parte de su
            // contrato normal, no son un bug real. Cualquier
            // RuntimeException NO esperada (NPE real, etc.) se deja
            // propagar -- eso SI es señal real para Jazzer.
            if (cause instanceof java.io.IOException || cause instanceof org.json.JSONException) {
                return;
            }
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new RuntimeException(cause);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}
