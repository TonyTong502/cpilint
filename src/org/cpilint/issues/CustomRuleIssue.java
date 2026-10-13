package org.cpilint.issues;

import java.util.Optional;

import org.cpilint.artifacts.IflowArtifactTag;

public final class CustomRuleIssue extends IssueBase {

	public CustomRuleIssue(Optional<String> ruleId, IflowArtifactTag tag, String message) {
		super(ruleId, tag, message);
	}
}
