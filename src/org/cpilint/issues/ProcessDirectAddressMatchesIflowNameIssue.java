package org.cpilint.issues;

import java.util.Optional;

import org.cpilint.artifacts.IflowArtifactTag;
import org.cpilint.model.SenderAdapter;

public final class ProcessDirectAddressMatchesIflowNameIssue extends SenderChannelIssueBase {

	public ProcessDirectAddressMatchesIflowNameIssue(Optional<String> ruleId, IflowArtifactTag tag,
			String channelName, String channelId, String address, String expectedPath) {
		super(ruleId, tag, SenderAdapter.PROCESSDIRECT, channelName, channelId, String.format(
			"Sender ProcessDirect channel '%s' (ID '%s') has address '%s', which must contain '%s' derived from integration-flow name '%s'.",
			channelName, channelId, address, expectedPath, tag.getName()));
	}

}
