package org.cpilint.rules;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.cpilint.RulesFile;
import org.cpilint.artifacts.IflowArtifact;
import org.cpilint.artifacts.ZipArchiveIflowArtifact;
import org.cpilint.consumers.IssueConsumer;
import org.cpilint.issues.Issue;
import org.cpilint.issues.ProcessDirectAddressMatchesIflowNameIssue;
import org.dom4j.DocumentHelper;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ProcessDirectAddressMatchesIflowNameRuleTest {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();

	@Test
	public void reportsMismatchUsingManifestNameRatherThanIdOrFilenames() throws Exception {
		IflowArtifact artifact = artifact("TST_PD_IFLOW_copy",
			channel("MessageFlow_4", "ProcessDirect", "Sender", address("/tst/pd/iflow2")), null);
		List<Issue> issues = inspect(artifact);
		assertEquals(1, issues.size());
		Issue issue = issues.get(0);
		assertTrue(issue instanceof ProcessDirectAddressMatchesIflowNameIssue);
		assertEquals(Optional.of("pd-address"), issue.getRuleId());
		assertTrue(issue.getTags().contains(artifact.getTag()));
		assertTrue(issue.getMessage().contains("MessageFlow_4"));
		assertTrue(issue.getMessage().contains("'/tst/pd/iflow2'"));
		assertTrue(issue.getMessage().contains("'/tst/pd/iflow/copy'"));
		assertTrue(issue.getMessage().contains("'TST_PD_IFLOW_copy'"));
	}

	@Test
	public void acceptsExactPathAndLiteralSubstringWithPrefixesAndSuffixes() throws Exception {
		String channels = channel("exact", "ProcessDirect", "Sender", address("/tst/pd/iflow/copy"))
			+ channel("substring", "ProcessDirect", "Sender", address("prefix/tst/pd/iflow/copySuffix"));
		assertTrue(inspect(artifact("TST_PD_IFLOW_copy", channels, null)).isEmpty());
	}

	@Test
	public void comparesAddressesCaseSensitively() throws Exception {
		assertEquals(1, inspect(artifact("TST_PD_IFLOW_copy",
			channel("sender", "ProcessDirect", "Sender", address("/TST/PD/IFLOW/COPY")), null)).size());
	}

	@Test
	public void ignoresReceiversAndChannelsWithoutTheExactName() throws Exception {
		String channels = channel("receiver", "ProcessDirect", "Receiver", address("/other"))
			+ channel("renamed", "OtherName", "Sender", address("/other"))
			+ channel("case", "processdirect", "Sender", address("/other"));
		assertTrue(inspect(artifact("TST_PD_IFLOW_copy", channels, null)).isEmpty());
	}

	@Test
	public void allowsFlowsWithoutProcessDirectChannels() throws Exception {
		assertTrue(inspect(artifact("TST_PD_IFLOW_copy", "", null)).isEmpty());
	}

	@Test
	public void reportsMissingEmptyAndMissingValueAddressesPerChannel() throws Exception {
		String channels = channel("missing", "ProcessDirect", "Sender", "")
			+ channel("empty", "ProcessDirect", "Sender", address(""))
			+ channel("no-value", "ProcessDirect", "Sender", "<ifl:property><key>address</key></ifl:property>")
			+ channel("valid", "ProcessDirect", "Sender", address("/tst/pd/iflow/copy"));
		List<Issue> issues = inspect(artifact("TST_PD_IFLOW_copy", channels, null));
		assertEquals(3, issues.size());
		for (Issue issue : issues) {
			assertTrue(issue.getMessage().contains("address ''"));
		}
	}

	@Test
	public void readsOnlyTheAddressPropertyUnderExtensionElements() throws Exception {
		String properties = "<ifl:property><key>not-address</key><value>/tst/pd/iflow/copy</value></ifl:property>"
			+ address("/wrong");
		assertEquals(1, inspect(artifact("TST_PD_IFLOW_copy",
			channel("sender", "ProcessDirect", "Sender", properties), null)).size());
	}

	@Test
	public void lowercasesIndependentlyOfDefaultLocaleAndPreservesOtherCharacters() throws Exception {
		Locale original = Locale.getDefault();
		try {
			Locale.setDefault(Locale.forLanguageTag("tr-TR"));
			assertTrue(inspect(artifact("I__O'Brien-Flow",
				channel("sender", "ProcessDirect", "Sender", address("/i//o'brien-flow")), null)).isEmpty());
		} finally {
			Locale.setDefault(original);
		}
	}

	@Test
	public void resolvesExternalParametersBeforeChecking() throws Exception {
		assertTrue(inspect(artifact("TST_PD_IFLOW_copy",
			channel("sender", "ProcessDirect", "Sender", address("{{pd_address}}")),
			"pd_address=/tst/pd/iflow/copy\n")).isEmpty());
	}

	@Test
	public void reportsResolvedExternalAddressRatherThanPlaceholder() throws Exception {
		IflowArtifact artifact = artifact("TST_PD_IFLOW_copy",
			channel("MessageFlow_4", "ProcessDirect", "Sender", address("{{PD_ADDRESS}}")),
			"#Fri Oct 30 07:29:02 UTC 2026\nPD_ADDRESS=/tst/pd/iflow2\n");
		assertResolvedMismatch(artifact);
	}

	private void assertResolvedMismatch(IflowArtifact artifact) throws Exception {
		assertEquals("/tst/pd/iflow2", artifact.getIflowXml().evaluateXpath(
			"//bpmn2:messageFlow[@name = 'ProcessDirect']/bpmn2:extensionElements/ifl:property[key = 'address']/value")
			.itemAt(0).getStringValue());
		List<Issue> issues = inspect(artifact);
		assertEquals(1, issues.size());
		assertTrue(issues.get(0).getMessage().contains("address '/tst/pd/iflow2'"));
		assertTrue(issues.get(0).getMessage().contains("must contain '/tst/pd/iflow/copy'"));
		assertFalse(issues.get(0).getMessage().contains("{{PD_ADDRESS}}"));
	}

	@Test
	public void reportsUnresolvedAndRuntimeAddressesRatherThanSilentlySkippingThem() throws Exception {
		String channels = channel("parameter", "ProcessDirect", "Sender", address("{{pd_address}}"))
			+ channel("runtime", "ProcessDirect", "Sender", address("${property.address}"));
		assertEquals(2, inspect(artifact("TST_PD_IFLOW_copy", channels, "")).size());
	}

	@Test
	public void usesNamespaceUrisRatherThanLiteralPrefixes() throws Exception {
		String channels = channel("sender", "ProcessDirect", "Sender", address("/tst/pd/iflow/copy"))
			.replace("bpmn2:", "b:").replace("ifl:", "i:");
		assertTrue(inspect(artifact("TST_PD_IFLOW_copy", channels, null)).isEmpty());
	}

	@Test
	public void remainsOptInAndCanCoexistWithExistingRules() throws Exception {
		Path rulesPath = temporaryFolder.newFile().toPath();
		Files.writeString(rulesPath, "<cpilint><rules><iflow-description-required/></rules></cpilint>");
		assertEquals(1, RulesFile.fromPath(rulesPath).getRules().size());
		Files.writeString(rulesPath, """
			<cpilint><rules>
				<iflow-description-required/>
				<process-direct-address-matches-iflow-name/>
			</rules></cpilint>
			""");
		assertEquals(2, RulesFile.fromPath(rulesPath).getRules().size());
	}

	@Test
	public void rejectsWrongFactoryElementsAndEmptyFlowNames() throws Exception {
		ProcessDirectAddressMatchesIflowNameRuleFactory factory = new ProcessDirectAddressMatchesIflowNameRuleFactory();
		assertFalse(factory.isFactoryFor("naming"));
		assertThrows(RuleFactoryError.class, () -> factory.createFrom(DocumentHelper.createElement("naming")));
		IflowArtifact artifact = artifact(" ", channel("sender", "ProcessDirect", "Sender", address("/")), null);
		assertThrows(RuleError.class, () -> inspect(artifact));
	}

	private List<Issue> inspect(IflowArtifact artifact) throws Exception {
		Path rulesPath = temporaryFolder.newFile().toPath();
		Files.writeString(rulesPath, """
			<cpilint><rules>
				<process-direct-address-matches-iflow-name id="pd-address"/>
			</rules></cpilint>
			""");
		org.cpilint.rules.Rule rule = RulesFile.fromPath(rulesPath).getRules().iterator().next();
		List<Issue> issues = new ArrayList<>();
		rule.startTesting(new IssueConsumer() {
			@Override
			public void consume(Issue issue) {
				issues.add(issue);
			}

			@Override
			public int issuesConsumed() {
				return issues.size();
			}
		});
		rule.inspect(artifact);
		rule.endTesting();
		return issues;
	}

	private static IflowArtifact artifact(String name, String channels, String parameters) throws Exception {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
			entry(zip, "META-INF/MANIFEST.MF",
				"Manifest-Version: 1.0\nBundle-Name: " + name + "\nBundle-SymbolicName: DIFFERENT_ID\n\n");
			entry(zip, ".project", "<projectDescription><name>DIFFERENT_PROJECT_NAME</name></projectDescription>");
			entry(zip, "src/main/resources/scenarioflows/integrationflow/DIFFERENT_FILENAME.iflw", """
				<bpmn2:definitions xmlns:bpmn2="http://www.omg.org/spec/BPMN/20100524/MODEL"
					xmlns:b="http://www.omg.org/spec/BPMN/20100524/MODEL"
					xmlns:ifl="http:///com.sap.ifl.model/Ifl.xsd"
					xmlns:i="http:///com.sap.ifl.model/Ifl.xsd">
					<bpmn2:collaboration>%s</bpmn2:collaboration>
				</bpmn2:definitions>
				""".formatted(channels));
			if (parameters != null) {
				entry(zip, "src/main/resources/parameters.prop", parameters);
			}
		}
		return ZipArchiveIflowArtifact.fromArchiveStream(new ByteArrayInputStream(bytes.toByteArray()));
	}

	private static void entry(ZipOutputStream zip, String path, String content) throws Exception {
		zip.putNextEntry(new ZipEntry(path));
		zip.write(content.getBytes(StandardCharsets.UTF_8));
		zip.closeEntry();
	}

	private static String channel(String id, String name, String direction, String addressProperty) {
		return """
			<bpmn2:messageFlow id="%s" name="%s"><bpmn2:extensionElements>
				<ifl:property><key>ComponentType</key><value>ProcessDirect</value></ifl:property>
				<ifl:property><key>direction</key><value>%s</value></ifl:property>
				%s
			</bpmn2:extensionElements></bpmn2:messageFlow>
			""".formatted(id, name, direction, addressProperty);
	}

	private static String address(String value) {
		return "<ifl:property><key>address</key><value>" + value + "</value></ifl:property>";
	}

}
