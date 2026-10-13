package org.cpilint.rules;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import org.cpilint.RulesFileError;
import org.dom4j.Element;

public final class CustomRuleFactory implements RuleFactory {

	private static final Set<String> RULE_NAMES = Set.of(
		"default-names-not-allowed-rule",
		"unused-parameters-rule",
		"allowed-headers-empty",
		"response-headers-allowed",
		"undeclared-data-type",
		"csrf-protection-required-with-exclude",
		"iflow-matches-name",
		"log-trace-level-enabled-rule",
		"disallowed-expressions",
		"disallowed-filter-xpath-property",
		"header-format",
		"property-format",
		"external-parameters-naming-convention"
	);
	private static final DateTimeFormatter ACTIVATION_DATE_FORMAT =
		DateTimeFormatter.ofPattern("dd-MM-uuuu").withResolverStyle(ResolverStyle.STRICT);

	@Override
	public boolean isFactoryFor(String ruleElementName) {
		return RULE_NAMES.contains(ruleElementName);
	}

	@Override
	public Rule createFrom(Element e) {
		String name = e.getName();
		if (!isFactoryFor(name)) {
			throw new RuleFactoryError("Cannot create Rule object from element '%s'".formatted(name));
		}
		return switch (name) {
			case "default-names-not-allowed-rule" ->
				new CustomRule(CustomRule.Type.DEFAULT_NAMES, List.of(), texts(e, "exclude"), List.of(), List.of(), List.of());
			case "unused-parameters-rule" ->
				new CustomRule(CustomRule.Type.UNUSED_PARAMETERS, List.of(), texts(e, "exclude"), List.of(), List.of(), List.of());
			case "allowed-headers-empty" ->
				new CustomRule(CustomRule.Type.ALLOWED_HEADERS_EMPTY, List.of(), List.of(),
					regexTexts(e, "include", name), regexTexts(e, "exclude", name), List.of());
			case "response-headers-allowed" ->
				new CustomRule(CustomRule.Type.RESPONSE_HEADERS_ALLOWED, List.of(), List.of(),
					regexTexts(e, "include", name), regexTexts(e, "exclude", name), List.of());
			case "undeclared-data-type" ->
				new CustomRule(CustomRule.Type.UNDECLARED_DATA_TYPE, List.of(), List.of(), List.of(), List.of(), List.of());
			case "csrf-protection-required-with-exclude" ->
				new CustomRule(CustomRule.Type.CSRF_WITH_FILTERS, List.of(), List.of(),
					regexTexts(e, "include", name), regexTexts(e, "exclude", name), List.of());
			case "iflow-matches-name" ->
				new CustomRule(CustomRule.Type.IFLOW_NAME, patterns(e, "naming-pattern", name, Pattern.DOTALL),
					List.of(), List.of(), List.of(), List.of());
			case "log-trace-level-enabled-rule" ->
				new CustomRule(CustomRule.Type.LOG_TRACE_PARAMETER, List.of(), texts(e, "exclude"),
					List.of(), List.of(), List.of());
			case "disallowed-expressions" ->
				new CustomRule(CustomRule.Type.DISALLOWED_EXPRESSIONS, patterns(e, "disallow", name, 0),
					List.of(), List.of(), List.of(), List.of());
			case "disallowed-filter-xpath-property" ->
				new CustomRule(CustomRule.Type.DISALLOWED_FILTER_XPATH, patterns(e, "disallow", name, 0),
					List.of(), List.of(), List.of(), List.of());
			case "header-format" ->
				new CustomRule(CustomRule.Type.HEADER_FORMAT, List.of(), List.of(), List.of(), List.of(),
					formatRules(e, name));
			case "property-format" ->
				new CustomRule(CustomRule.Type.PROPERTY_FORMAT, List.of(), List.of(), List.of(), List.of(),
					formatRules(e, name));
			case "external-parameters-naming-convention" ->
				new CustomRule(CustomRule.Type.EXTERNAL_PARAMETER_NAMES,
					patterns(e, "naming-pattern", name, 0), List.of(), List.of(), List.of(), List.of());
			default -> throw new AssertionError("Unexpected rule element: " + name);
		};
	}

	private static List<String> texts(Element parent, String childName) {
		return parent.elements(childName).stream()
			.map(Element::getText)
			.map(String::trim)
			.collect(Collectors.toList());
	}

	private static List<String> regexTexts(Element parent, String childName, String ruleName) {
		List<String> expressions = texts(parent, childName);
		expressions.forEach(expression -> compile(expression, ruleName, 0));
		return expressions;
	}

	private static List<Pattern> patterns(Element parent, String childName, String ruleName, int flags) {
		List<String> expressions = texts(parent, childName);
		if (expressions.isEmpty()) {
			throw new RulesFileError("Element '%s' must contain at least one '%s' element".formatted(ruleName, childName));
		}
		return expressions.stream()
			.map(expression -> compile(expression, ruleName, flags))
			.toList();
	}

	private static Pattern compile(String expression, String ruleName, int flags) {
		if (expression.isEmpty()) {
			throw new RulesFileError("Element '%s' contains an empty regular expression".formatted(ruleName));
		}
		try {
			return Pattern.compile(expression, flags);
		} catch (PatternSyntaxException e) {
			throw new RulesFileError("Invalid regular expression in '%s': %s".formatted(ruleName, e.getDescription()), e);
		}
	}

	private static List<CustomRule.FormatRule> formatRules(Element parent, String ruleName) {
		String exceptionText = parent.elementText("exceptions");
		Set<String> exceptions = exceptionText == null || exceptionText.isBlank()
			? Set.of()
			: java.util.Arrays.stream(exceptionText.split(",", -1))
				.map(String::trim)
				.filter(value -> !value.isEmpty())
				.collect(Collectors.toUnmodifiableSet());
		List<Element> elements = parent.elements("rule");
		if (elements.isEmpty()) {
			throw new RulesFileError("Element '%s' must contain at least one 'rule' element".formatted(ruleName));
		}
		return elements.stream().map(element -> {
			String activationText = element.elementText("activationDate");
			String expression = element.elementText("ruleExpression");
			if (activationText == null || expression == null || expression.isBlank()) {
				throw new RulesFileError("Each 'rule' in '%s' must contain 'activationDate' and non-empty 'ruleExpression'".formatted(ruleName));
			}
			LocalDate activationDate;
			try {
				activationDate = LocalDate.parse(activationText.trim(), ACTIVATION_DATE_FORMAT);
			} catch (DateTimeParseException e) {
				throw new RulesFileError("Invalid activationDate '%s' in '%s'; expected dd-MM-yyyy".formatted(activationText, ruleName), e);
			}
			return new CustomRule.FormatRule(activationDate, compile(expression.trim(), ruleName, 0), exceptions);
		}).toList();
	}
}
