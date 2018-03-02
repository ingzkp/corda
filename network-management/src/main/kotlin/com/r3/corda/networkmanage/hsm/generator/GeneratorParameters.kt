package com.r3.corda.networkmanage.hsm.generator

import com.r3.corda.networkmanage.common.utils.ShowHelpException
import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import joptsimple.OptionParser
import net.corda.core.internal.isRegularFile
import net.corda.nodeapi.internal.config.parseAs
import net.corda.nodeapi.internal.crypto.CertificateType
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Holds configuration necessary for user's authentication against HSM.
 */
data class UserAuthenticationParameters(val username: String,
                                        val authMode: AuthMode,
                                        val authToken: String?, // password or path to the key file, depending on the [authMode]
                                        val keyFilePassword: String?) // used only if authMode == [AuthMode.KEY_FILE]

/**
 * Supported authentication modes.
 */
enum class AuthMode {
    PASSWORD, CARD_READER, KEY_FILE
}

/**
 * Holds generator parameters.
 */
data class GeneratorParameters(val hsmHost: String,
                               val hsmPort: Int,
                               val trustStoreDirectory: Path,
                               val trustStorePassword: String,
                               val userConfigs: List<UserAuthenticationParameters>,
                               val certConfig: CertificateConfiguration)

/**
 * Holds certificate specific configuration.
 */
data class CertificateConfiguration(val keyGroup: String,
                                    val keySpecifier: Int,
                                    val storeKeysExternal: Boolean,
                                    val certificateType: CertificateType,
                                    val rootKeyGroup: String?,
                                    val subject: String, // it is certificate [X500Name] subject
                                    val validDays: Int,
                                    val crlDistributionUrl: String?,
                                    val crlIssuer: String?, // X500 name of the issuing authority e.g. "L=New York, C=US, OU=Org Unit, CN=Service Name"
                                    val keyOverride: Int, // 1 for allow and 0 deny
                                    val keyExport: Int, // 1 for allow, 0 for deny
                                    val keyCurve: String, // we use "NIST-P256", check Utimaco docs for other options
                                    val keyGenMechanism: Int) // MECH_KEYGEN_UNCOMP = 4 or MECH_RND_REAL = 0

/**
 * Holds arguments for command line options.
 */
data class CommandLineOptions(val configFile: Path) {
    init {
        check(configFile.isRegularFile()) { "Config file $configFile does not exist" }
    }
}

/**
 * Parses key generator command line options.
 */
fun parseCommandLine(vararg args: String): CommandLineOptions {
    val optionParser = OptionParser()
    val configFileArg = optionParser
            .accepts("config-file", "The path to the config file")
            .withRequiredArg()
            .describedAs("filepath")
    val helpOption = optionParser.acceptsAll(listOf("h", "?", "help"), "show help").forHelp()

    val optionSet = optionParser.parse(*args)
    // Print help and exit on help option or if there are missing options.
    if (optionSet.has(helpOption) || !optionSet.has(configFileArg)) {
        throw ShowHelpException(optionParser)
    }

    val configFile = Paths.get(optionSet.valueOf(configFileArg)).toAbsolutePath()

    return CommandLineOptions(configFile)
}

/**
 * Parses a configuration file, which contains all the configuration - i.e. for user and certificate parameters.
 */
fun parseParameters(configFile: Path): GeneratorParameters {
    return ConfigFactory
            .parseFile(configFile.toFile(), ConfigParseOptions.defaults().setAllowMissing(true))
            .resolve()
            .parseAs(false)
}