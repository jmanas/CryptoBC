package demos;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Security;
import java.util.Map;

/**
 * Alternative to
 * http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
 */
public class Setup {
    public static void BC()
            throws Exception {
        removeCryptographyRestrictions();
        Security.addProvider(new BouncyCastleProvider());
    }

    private static void removeCryptographyRestrictions()
            throws Exception {
        final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
        final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
        final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

        final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
        isRestrictedField.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(isRestrictedField, isRestrictedField.getModifiers() & ~Modifier.FINAL);
        isRestrictedField.set(null, false);

        final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
        defaultPolicyField.setAccessible(true);
        final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

        final Field perms = cryptoPermissions.getDeclaredField("perms");
        perms.setAccessible(true);
        Map<?, ?> map = (Map<?, ?>) perms.get(defaultPolicy);
        map.clear();

        final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        defaultPolicy.add((Permission) instance.get(null));
    }
}
