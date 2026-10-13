# Building CPILint

To build CPILint from source, install a Java 17 JDK and [Apache Maven](https://maven.apache.org/).

Run the following command from the repository root:

```text
mvn clean package
```

Maven resolves the application and XML Schema 1.1 dependencies and creates the standard JAR artifact at `target/cpilint-1.1.0.jar`.

`dist-files/samples/FerringRules.xml` includes the policy configuration supplied with the custom-rule repository. It retains the original rule element names and organization-specific configuration, with only `<design-guidelines-check/>` omitted because that rule calls SAP's separately configured Design Guidelines API.

The project includes these 13 custom rule elements: `default-names-not-allowed-rule`, `unused-parameters-rule`, `allowed-headers-empty`, `response-headers-allowed`, `undeclared-data-type`, `csrf-protection-required-with-exclude`, `iflow-matches-name`, `log-trace-level-enabled-rule`, `disallowed-expressions`, `disallowed-filter-xpath-property`, `header-format`, `property-format`, and `external-parameters-naming-convention`.

CSRF and `allowed-headers-empty` inclusion/exclusion values are regular expressions matched against the integration-flow ID. `response-headers-allowed` inclusion/exclusion expressions are matched against each configured response-header value. Header-format and property-format rules activate when the configured date is reached; this implementation uses the current date because the artifact model does not expose an integration-flow creation date. Disallowed-expression checks scan flow XML, Groovy scripts, and external-parameter files; Java archives are skipped.