package org.cpilint.rules;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cpilint.artifacts.ArtifactResource;
import org.cpilint.artifacts.ArtifactResourceType;
import org.cpilint.artifacts.IflowArtifact;
import org.cpilint.artifacts.IflowArtifactTag;
import org.cpilint.consumers.IssueConsumer;
import org.cpilint.issues.CsrfProtectionRequiredIssue;
import org.cpilint.issues.CustomRuleIssue;
import org.cpilint.issues.Issue;
import org.cpilint.model.SenderAdapter;
import org.cpilint.model.XmlModel;
import org.cpilint.model.XmlModelFactory;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.XPath;
import org.dom4j.io.SAXReader;

import net.sf.saxon.s9api.XdmItem;
import net.sf.saxon.s9api.XdmValue;

final class CustomRule extends RuleBase {

	enum Type {
		DEFAULT_NAMES,
		UNUSED_PARAMETERS,
		ALLOWED_HEADERS_EMPTY,
		RESPONSE_HEADERS_ALLOWED,
		UNDECLARED_DATA_TYPE,
		CSRF_WITH_FILTERS,
		IFLOW_NAME,
		LOG_TRACE_PARAMETER,
		DISALLOWED_EXPRESSIONS,
		DISALLOWED_FILTER_XPATH,
		HEADER_FORMAT,
		PROPERTY_FORMAT,
		EXTERNAL_PARAMETER_NAMES
	}

	record FormatRule(LocalDate activationDate, Pattern expression, Set<String> exceptions) {}

	private static final Map<String, Pattern> ACTIVITY_DEFAULT_NAMES = Map.ofEntries(
		Map.entry("Enricher", Pattern.compile("Content Modifier \\d")),
		Map.entry("ProcessCall", Pattern.compile("Process Call \\d")),
		Map.entry("ProcessCallElement", Pattern.compile("Process Call( Element)? \\d")),
		Map.entry("XmlValidator", Pattern.compile("XML Validator \\d")),
		Map.entry("EDIValidator", Pattern.compile("EDI Validator \\d")),
		Map.entry("XMLtoEDIConverter", Pattern.compile("XML to EDI Converter \\d")),
		Map.entry("Mapping", Pattern.compile("(Message|Operation|XSLT) Mapping \\d")),
		Map.entry("XmlToCsvConverter", Pattern.compile("XML to CSV Converter \\d")),
		Map.entry("JsonToXmlConverter", Pattern.compile("JSON to XML Converter \\d")),
		Map.entry("CsvToXmlConverter", Pattern.compile("CSV to XML Converter \\d")),
		Map.entry("XmlToJsonConverter", Pattern.compile("XML to JSON Converter \\d")),
		Map.entry("DBstorage", Pattern.compile("(Delete|Get|Select|Write) \\d")),
		Map.entry("Persist", Pattern.compile("Persist \\d")),
		Map.entry("Encoder", Pattern.compile("(MIME Multipart Encoder|Base64 Encoder|ZIP Compression|GZIP Compression) \\d")),
		Map.entry("Decoder", Pattern.compile("(GZIP Decompression|ZIP Decompression|Base64 Decoder|MIME Multipart Decoder) \\d")),
		Map.entry("Filter", Pattern.compile("Filter \\d")),
		Map.entry("VerifySign", Pattern.compile("PKCS7 Signature Verifier \\d")),
		Map.entry("EDIExtractor", Pattern.compile("EDI Extractor \\d")),
		Map.entry("EDItoXMLConverter", Pattern.compile("EDI to XML Converter \\d")),
		Map.entry("SimpleSignMessage", Pattern.compile("Simple Signer \\d")),
		Map.entry("Encrypt", Pattern.compile("PKCS7Encryptor \\d")),
		Map.entry("PgpEncrypt", Pattern.compile("PGPEncryptor \\d")),
		Map.entry("Decrypt", Pattern.compile("PKCS7Decryptor \\d")),
		Map.entry("PgpDecrypt", Pattern.compile("PGPDecryptor \\d")),
		Map.entry("Aggregator", Pattern.compile("Aggregator \\d")),
		Map.entry("Gather", Pattern.compile("Gather \\d")),
		Map.entry("XMLDigitalSignMessage", Pattern.compile("XML Signer \\d")),
		Map.entry("SignMessage", Pattern.compile("PKCS7 Signer \\d")),
		Map.entry("XmlModifier", Pattern.compile("XML Modifier \\d")),
		Map.entry("MessageDigest", Pattern.compile("Message Digest \\d")),
		Map.entry("XMLDigitalVerifySign", Pattern.compile("XML Signature Verifier \\d")),
		Map.entry("Variables", Pattern.compile("Write Variables \\d")),
		Map.entry("Splitter", Pattern.compile("(EDI|Zip|Iterating|General|IDoc|PKCS#7/CMS|Tar) Splitter \\d"))
	);
	private static final Map<String, Pattern> SERVICE_DEFAULT_NAMES = Map.of(
		"Send", Pattern.compile("Send \\d"),
		"contentEnricherWithLookup", Pattern.compile("Content Enricher \\d"),
		"PollEnrich", Pattern.compile("Poll Enrich \\d"),
		"ExternalCall", Pattern.compile("Request Reply \\d"),
		"ExclusiveGateway", Pattern.compile("Router \\d")
	);
	private static final Pattern VALUE_CELL = Pattern.compile("(?is)<cell\\s+[^>]*id\\s*=\\s*(['\"])Value\\1[^>]*>.*?</cell>");
	private static final Pattern NEW_SYNTAX_FIELD = Pattern.compile("^(Name|Type|Datatype):=:(.*)$", Pattern.DOTALL);
	private static final Pattern CELL = Pattern.compile("(?is)<cell\\b[^>]*id\\s*=\\s*(['\"])Name\\1[^>]*>(.*?)</cell>");

	private final Type type;
	private final List<Pattern> patterns;
	private final List<String> exclusions;
	private final List<String> inclusions;
	private final List<FormatRule> formatRules;

	CustomRule(Type type, List<Pattern> patterns, List<String> exclusions, List<String> inclusions,
			List<String> valueExclusions, List<FormatRule> formatRules) {
		this.type = type;
		this.patterns = List.copyOf(patterns);
		List<String> allExclusions = new ArrayList<>(exclusions);
		allExclusions.addAll(valueExclusions);
		this.exclusions = List.copyOf(allExclusions);
		this.inclusions = List.copyOf(inclusions);
		this.formatRules = List.copyOf(formatRules);
	}

	@Override
	public void inspect(IflowArtifact iflow) {
		switch (type) {
			case DEFAULT_NAMES -> inspectDefaultNames(iflow);
			case UNUSED_PARAMETERS -> inspectUnusedParameters(iflow);
			case ALLOWED_HEADERS_EMPTY -> inspectAllowedHeaders(iflow);
			case RESPONSE_HEADERS_ALLOWED -> inspectResponseHeaders(iflow);
			case UNDECLARED_DATA_TYPE -> inspectDeclaredDataTypes(iflow);
			case CSRF_WITH_FILTERS -> inspectCsrf(iflow);
			case IFLOW_NAME -> inspectIflowName(iflow.getTag());
			case LOG_TRACE_PARAMETER -> inspectLogTraceParameter(iflow);
			case DISALLOWED_EXPRESSIONS -> inspectDisallowedExpressions(iflow);
			case DISALLOWED_FILTER_XPATH -> inspectFilterExpressions(iflow);
			case HEADER_FORMAT -> inspectFormat(iflow, true);
			case PROPERTY_FORMAT -> inspectFormat(iflow, false);
			case EXTERNAL_PARAMETER_NAMES -> inspectExternalParameterNames(iflow);
		}
	}

	private void inspectDefaultNames(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		Document document = parseFlow(iflow);
		for (Element element : selectNodes(document,
				"//bpmn2:callActivity | //bpmn2:serviceTask | //bpmn2:exclusiveGateway")) {
			String name = element.attributeValue("name");
			String id = element.attributeValue("id");
			String activityType = property(element, "activityType");
			String subActivityType = property(element, "subActivityType");
			if (name == null || isExcluded(id) || isExcluded(activityType)) {
				continue;
			}
			Pattern defaultName = ACTIVITY_DEFAULT_NAMES.get(activityType);
			if (defaultName == null && "Script".equals(activityType) && "GroovyScript".equals(subActivityType)) {
				defaultName = Pattern.compile("Groovy Script \\d");
			}
			if (defaultName == null && element.getName().equals("serviceTask")) {
				defaultName = SERVICE_DEFAULT_NAMES.get(activityType);
			}
			if (defaultName != null && defaultName.matcher(name).matches()) {
				report(tag, "Default name '%s' for activity type '%s' was found.".formatted(name, activityType));
			}
		}
		for (Element process : selectNodes(document, "//bpmn2:process | //bpmn2:subProcess")) {
			String name = process.attributeValue("name");
			String id = process.attributeValue("id");
			if (name == null || isExcluded(id)) {
				continue;
			}

			if (id != null && id.startsWith("SubProcess")
					&& name.matches("Exception Subprocess \\d") && !isExcluded("Exception Subprocess")) {
				report(tag, "Default name '%s' for Exception Subprocess was found.".formatted(name));
			} else if (id != null && id.startsWith("Process")
					&& (name.matches("Integration Process \\d") || name.matches("Local Integration Process( \\d)?"))) {
				report(tag, "Default process name '%s' was found.".formatted(name));
			}
		}
		for (ArtifactResource resource : iflow.getResourcesByType(ArtifactResourceType.GROOVY_SCRIPT)) {
			if (resource.getName().toLowerCase(java.util.Locale.ROOT).matches("script\\d\\.groovy")) {
				report(tag, "Default Groovy script filename '%s' was found.".formatted(resource.getName()));
			}
		}
		for (ArtifactResource resource : iflow.getResourcesByType(ArtifactResourceType.XSLT_MAPPING)) {
			if (resource.getName().toLowerCase(java.util.Locale.ROOT).matches("xsltmapping\\d\\.xslt?")) {
				report(tag, "Default XSLT mapping filename '%s' was found.".formatted(resource.getName()));
			}
		}
	}

	private static List<Element> selectNodes(Document document, String expression) {
		XPath xpath = DocumentHelper.createXPath(expression);
		xpath.setNamespaceURIs(XPATH_NAMESPACES);
		return xpath.selectNodes(document).stream().map(Element.class::cast).toList();
	}

	private void inspectUnusedParameters(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		for (ArtifactResource resource : externalParameters(iflow)) {
			if (!resource.getName().equals("parameters.propdef")) {
				continue;
			}
			for (String parameter : parameterDefinitionNames(resource)) {
				if (!isExcluded(parameter) && !isExcluded(tag.getId() + ":" + parameter)
						&& !parameterIsUsed(parameter, iflow)) {
					report(tag, "External parameter '%s' is not used.".formatted(parameter));
				}
			}
		}
	}

	private boolean parameterIsUsed(String name, IflowArtifact iflow) {
		Pattern wholeWord = Pattern.compile("\\b" + Pattern.quote(name) + "\\b");
		String rawXml = readFlowXml(iflow);
		if (rawXml.contains("{{" + name + "}}") || wholeWord.matcher(rawXml).find()) {
			return true;
		}
		for (ArtifactResourceType resourceType : TEXT_RESOURCE_TYPES) {
			if (resourceType == ArtifactResourceType.IFLOW) {
				continue;
			}
			for (ArtifactResource resource : iflow.getResourcesByType(resourceType)) {
				if (wholeWord.matcher(readResource(resource)).find()) {
					return true;
				}
			}
		}
		return false;
	}

	private void inspectAllowedHeaders(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		XdmValue result = iflow.getIflowXml().evaluateXpath(
			"//bpmn2:collaboration/bpmn2:extensionElements/ifl:property[key='allowedHeaderList']/value/text()");
		if (result.isEmpty() && appliesTo(tag.getId())) {
			report(tag, "Allowed headers are empty for this integration flow.");
		}
	}

	private void inspectResponseHeaders(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		XdmValue result = iflow.getIflowXml().evaluateXpath(
			"//bpmn2:messageFlow/bpmn2:extensionElements/ifl:property[key='allowedResponseHeaders']/value/text()");
		for (XdmItem item : result) {
			String configured = item.getStringValue();
			for (String header : configured.split("\\|", -1)) {
				if (!headerAllowed(header)) {
					report(tag, "Response header '%s' is not allowed.".formatted(header));
					break;
				}
			}
		}
	}

	private boolean headerAllowed(String header) {
		if (!inclusions.isEmpty()) {
			return inclusions.stream().anyMatch(expression -> header.matches(expression));
		}
		return exclusions.stream().noneMatch(expression -> header.matches(expression));
	}

	private boolean appliesTo(String id) {
		if (!inclusions.isEmpty()) {
			return inclusions.stream().anyMatch(expression -> id.matches(expression));
		}
		return exclusions.stream().noneMatch(expression -> id.matches(expression));
	}

	private void inspectCsrf(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		if (!appliesTo(tag.getId())) {
			return;
		}
		XmlModel model = XmlModelFactory.getModelFor(iflow.getIflowXml());
		String xpath = model.xpathForSenderChannels(SenderAdapter.HTTPS, model.channelPredicateForNoCsrfProtection());
		for (XdmItem item : iflow.getIflowXml().evaluateXpath(xpath)) {
			net.sf.saxon.s9api.XdmNode node = (net.sf.saxon.s9api.XdmNode)item;
			consumer.consume(new CsrfProtectionRequiredIssue(ruleId, tag,
				model.getChannelNameFromElement(node), model.getChannelIdFromElement(node)));
		}
	}

	private void inspectIflowName(IflowArtifactTag tag) {
		if (patterns.stream().noneMatch(expression -> expression.matcher(tag.getName()).find())) {
			report(tag, "Integration flow name '%s' does not match any configured naming pattern.".formatted(tag.getName()));
		}
	}

	private void inspectLogTraceParameter(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		if (isExcluded(tag.getId())) {
			return;
		}
		String xml = readFlowXml(iflow);
		if (!xml.contains("logBody.groovy")) {
			return;
		}
		boolean propertyPresent = iflow.getIflowXml().evaluateXpath(
			"//bpmn2:callActivity/bpmn2:extensionElements/ifl:property/value[contains(., 'FER_LogTraceLevelEnabled')]")
			.size() > 0;
		boolean parameterPresent = externalParameters(iflow).stream()
			.filter(resource -> resource.getName().equals("parameters.propdef"))
			.flatMap(resource -> parameterDefinitionNames(resource).stream())
			.anyMatch("FER_LogTraceLevelEnabled"::equals);
		if (!propertyPresent || !parameterPresent) {
			report(tag, "External parameter and/or property 'FER_LogTraceLevelEnabled' is missing while logBody.groovy is used.");
		}
	}

	private void inspectDisallowedExpressions(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		checkExpressions(tag, "integration flow XML", readFlowXml(iflow));
		for (ArtifactResourceType type : List.of(ArtifactResourceType.GROOVY_SCRIPT, ArtifactResourceType.EXTERNAL_PARAMETERS)) {
			for (ArtifactResource resource : iflow.getResourcesByType(type)) {
				checkExpressions(tag, resource.getName(), readResource(resource));
			}
		}
	}

	private void checkExpressions(IflowArtifactTag tag, String source, String content) {
		for (Pattern expression : patterns) {
			if (expression.matcher(content).find()) {
				report(tag, "Disallowed expression '%s' was found in '%s'.".formatted(expression.pattern(), source));
			}
		}
	}

	private void inspectFilterExpressions(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		XdmValue values = iflow.getIflowXml().evaluateXpath(
			"//bpmn2:extensionElements[ifl:property[key='activityType' and value='Filter']]/ifl:property[key='wrapContent']/value/text()");
		for (XdmItem item : values) {
			for (Pattern expression : patterns) {
				if (expression.matcher(item.getStringValue()).find()) {
					report(tag, "Disallowed Filter XPath expression '%s' was found.".formatted(expression.pattern()));
				}
			}
		}
	}

	private void inspectFormat(IflowArtifact iflow, boolean header) {
		IflowArtifactTag tag = iflow.getTag();
		String tableKey = header ? "headerTable" : "propertyTable";
		String kind = header ? "Header" : "Property";
		XdmValue values = iflow.getIflowXml().evaluateXpath(
			"//ifl:property[key='%s']/value/text()".formatted(tableKey));
		Set<String> names = new HashSet<>();
		for (XdmItem item : values) {
			names.addAll(tableNames(item.getStringValue()));
		}
		String scriptMethod = header ? "setHeader" : "setProperty";
		Pattern setter = Pattern.compile("\\." + scriptMethod + "\\(\"([^\"]+)\"\\s*,");
		for (ArtifactResource script : iflow.getResourcesByType(ArtifactResourceType.GROOVY_SCRIPT)) {
			Matcher matcher = setter.matcher(readResource(script));
			while (matcher.find()) {
				names.add(matcher.group(1));
			}
		}
		LocalDate today = LocalDate.now();
		for (FormatRule format : formatRules) {
			if (today.isBefore(format.activationDate())) {
				continue;
			}
			for (String value : names) {
				if (!format.exceptions().contains(value) && !format.expression().matcher(value).find()) {
					report(tag, "%s '%s' does not match format '%s'.".formatted(kind, value, format.expression().pattern()));
				}
			}
		}
	}

	private Set<String> tableNames(String table) {
		String decoded = table.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'");
		Matcher cellMatcher = CELL.matcher(decoded);
		Set<String> names = new HashSet<>();
		while (cellMatcher.find()) {
			names.add(cellMatcher.group(2).trim());
		}
		return names;
	}

	private void inspectDeclaredDataTypes(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		XdmValue values = iflow.getIflowXml().evaluateXpath(
			"//bpmn2:callActivity/bpmn2:extensionElements/ifl:property[key='headerTable' or key='propertyTable' or starts-with(key,'HEADER_')]/value/text()");
		for (XdmItem item : values) {
			checkDataTypes(tag, item.getStringValue());
		}
	}

	private void checkDataTypes(IflowArtifactTag tag, String content) {
		String currentName = null;
		String currentType = null;
		String currentDataType = null;
		for (String field : content.split(":;", -1)) {
			Matcher matcher = NEW_SYNTAX_FIELD.matcher(field);
			if (!matcher.matches()) {
				continue;
			}
			if (matcher.group(1).equals("Name")) {
				if ("expression".equalsIgnoreCase(currentType) && (currentDataType == null || currentDataType.isEmpty())) {
					report(tag, "Expression content modifier property '%s' has no datatype.".formatted(currentName));
				}
				currentName = matcher.group(2).trim();
				currentType = null;
				currentDataType = null;
			} else {
				switch (matcher.group(1)) {
					case "Type" -> currentType = matcher.group(2).trim();
					case "Datatype" -> currentDataType = matcher.group(2).trim();
				default -> throw new AssertionError("Unexpected content modifier field");
				}
			}
		}
		if ("expression".equalsIgnoreCase(currentType) && (currentDataType == null || currentDataType.isEmpty())) {
			report(tag, "Expression content modifier property '%s' has no datatype.".formatted(currentName));
		}
		String withoutValues = VALUE_CELL.matcher(content.replace("&lt;", "<").replace("&gt;", ">"))
			.replaceAll("<cell id='Value'></cell>");
		if (!withoutValues.contains("<row")) {
			return;
		}
		try {
			Document document = secureReader().read(new StringReader("<root>" + withoutValues + "</root>"));
			for (Element row : document.getRootElement().elements("row")) {
				String name = null;
				String valueType = null;
				String dataType = null;
				for (Element cell : row.elements("cell")) {
					String id = cell.attributeValue("id");
					if ("Name".equals(id)) {
						name = cell.getTextTrim();
					} else if ("Type".equals(id)) {
						valueType = cell.getTextTrim();
					} else if ("Datatype".equals(id)) {
						dataType = cell.getTextTrim();
					}
				}
				if ("expression".equalsIgnoreCase(valueType) && (dataType == null || dataType.isEmpty())) {
					report(tag, "Expression content modifier property '%s' has no datatype.".formatted(name));
				}
			}
		} catch (DocumentException e) {
			throw new RuleError("Unable to parse content modifier table while checking datatypes", e);
		}
	}

	private void inspectExternalParameterNames(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		Pattern namingPattern = patterns.get(0);
		for (ArtifactResource resource : externalParameters(iflow)) {
			if (!resource.getName().equals("parameters.prop")) {
				continue;
			}
			Properties properties = new Properties();
			try (InputStream stream = resource.getContents()) {
				properties.load(stream);
			} catch (IOException e) {
				throw new RuleError("Unable to read external parameters for iflow '%s'".formatted(tag.getName()), e);
			}
			for (String name : properties.stringPropertyNames()) {
				if (!namingPattern.matcher(name).matches()) {
					report(tag, "External parameter name '%s' does not match '%s'.".formatted(name, namingPattern.pattern()));
				}
			}
		}
	}

	private List<String> parameterDefinitionNames(ArtifactResource resource) {
		try (InputStream stream = resource.getContents()) {
			Document document = secureReader().read(stream);
			List<String> names = new ArrayList<>();
			for (Element parameter : document.getRootElement().elements()) {
				if (parameter.getName().equalsIgnoreCase("param_references")) {
					for (Element reference : parameter.elements()) {
						String key = reference.attributeValue("param_key");
						if (key != null && !key.isBlank()) {
							names.add(key.trim());
						}
					}
				} else {
					String name = parameter.elementText("name");
					if (name != null && !name.isBlank()) {
						names.add(name.trim());
					}
				}
			}
			return names;
		} catch (IOException | DocumentException e) {
			throw new RuleError("Unable to parse external parameter definitions '%s'".formatted(resource.getName()), e);
		}
	}

	private static final Set<ArtifactResourceType> TEXT_RESOURCE_TYPES = Set.of(
		ArtifactResourceType.IFLOW,
		ArtifactResourceType.GROOVY_SCRIPT,
		ArtifactResourceType.JAVASCRIPT_SCRIPT,
		ArtifactResourceType.XSLT_MAPPING,
		ArtifactResourceType.OPERATION_MAPPING,
		ArtifactResourceType.JSON,
		ArtifactResourceType.XSD
	);

	private static final Map<String, String> XPATH_NAMESPACES = Map.of(
		"bpmn2", "http://www.omg.org/spec/BPMN/20100524/MODEL",
		"ifl", "http:///com.sap.ifl.model/Ifl.xsd"
	);

	private static SAXReader secureReader() {
		SAXReader reader = new SAXReader();
		try {
			reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
			reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
		} catch (org.xml.sax.SAXException e) {
			throw new RuleError("Unable to configure a secure XML parser", e);
		}
		return reader;
	}

	private static Document parseFlow(IflowArtifact iflow) {
		try (InputStream stream = iflow.getIflowXml().getRawDocument()) {
			return secureReader().read(stream);
		} catch (IOException | DocumentException e) {
			throw new RuleError("Unable to parse integration flow XML for default-name checks", e);
		}
	}

	private static String property(Element element, String name) {
		for (Element extension : element.elements()) {
			if (!extension.getName().equals("extensionElements")) {
				continue;
			}
			for (Element property : extension.elements()) {
				if (!property.getName().equals("property")) {
					continue;
				}
				String key = property.elementText("key");
				if (name.equals(key)) {
					return property.elementText("value");
				}
			}
		}
		return null;
	}

	private boolean isExcluded(String value) {
		return value != null && exclusions.contains(value);
	}

	private List<ArtifactResource> externalParameters(IflowArtifact iflow) {
		return List.copyOf(iflow.getResourcesByType(ArtifactResourceType.EXTERNAL_PARAMETERS));
	}

	private static String readFlowXml(IflowArtifact iflow) {
		try (InputStream stream = iflow.getIflowXml().getRawDocument()) {
			return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new RuleError("Unable to read integration flow XML", e);
		}
	}

	private static String readResource(ArtifactResource resource) {
		try (InputStream stream = resource.getContents()) {
			return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new RuleError("Unable to read artifact resource '%s'".formatted(resource.getName()), e);
		}
	}

	private void report(IflowArtifactTag tag, String message) {
		consumer.consume(new CustomRuleIssue(ruleId, tag, message));
	}
}
