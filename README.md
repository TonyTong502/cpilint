![CPILint logo](graphics/cpilint.png)

# CPILint

This repository is based on [mwittrock/cpilint](https://github.com/mwittrock/cpilint). Its Ant/Ivy build has been replaced with Maven, and custom rules from [nunomcpereira/cpilint_custom](https://github.com/nunomcpereira/cpilint_custom) have been added.

## What is CPILint?

CPILint is a command-line tool that automates your SAP Cloud Integration governance. It ships with a range of built-in rules covering topics like developer guidelines, naming conventions and security. You choose the rules you want to put in place, and CPILint does the heavy lifting of checking your integration flows for compliance.

## Building

Build with Java 17 and Maven:

```text
mvn clean package
```

See [BUILDING.md](BUILDING.md) for build details and the custom-rule notes.

## Documentation

Instructions on using the original CPILint functionality are available in the [upstream wiki](https://github.com/mwittrock/cpilint/wiki).

### ProcessDirect address naming

Enable the optional rule in your rules XML:

```xml
<cpilint>
    <rules>
        <process-direct-address-matches-iflow-name/>
    </rules>
</cpilint>
```

The rule uses the integration flow name already loaded from `META-INF/MANIFEST.MF` (`Bundle-Name`), It lowercases the name, replaces each underscore with `/`, and prepends `/`; all other characters remain unchanged. For example, `PD_IFLOW` produces `/pd/iflow`.

It checks Process Direct Address against integration flow name, to make sure the address contains produced text above.

## License

CPILint is licensed under the MIT open-source license. For the full license text, please see the LICENSE.txt file in the root of the repository.
