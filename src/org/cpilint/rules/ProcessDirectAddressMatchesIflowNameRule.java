package org.cpilint.rules;

import java.util.Iterator;
import java.util.Locale;

import org.cpilint.IflowXml;
import org.cpilint.artifacts.IflowArtifact;
import org.cpilint.artifacts.IflowArtifactTag;
import org.cpilint.issues.ProcessDirectAddressMatchesIflowNameIssue;
import org.cpilint.model.XmlModel;
import org.cpilint.model.XmlModelFactory;

import net.sf.saxon.s9api.XdmItem;
import net.sf.saxon.s9api.XdmValue;

final class ProcessDirectAddressMatchesIflowNameRule extends RuleBase {

	@Override
	public void inspect(IflowArtifact iflow) {
		IflowArtifactTag tag = iflow.getTag();
		if (tag.getName().isBlank()) {
			throw new RuleError("Cannot derive a ProcessDirect address from an empty integration-flow name");
		}
		String expectedPath = "/" + tag.getName().toLowerCase(Locale.ROOT).replace('_', '/');
		IflowXml iflowXml = iflow.getIflowXml();
		XmlModel model = XmlModelFactory.getModelFor(iflowXml);
		XdmValue result = iflowXml.executeXquery(model.xqueryForNamedProcessDirectSenderChannels());
		if (result.size() % 3 != 0) {
			throw new RuleError(String.format("Unexpected size (%d) of sequence returned by XQuery query", result.size()));
		}
		Iterator<XdmItem> items = result.iterator();
		while (items.hasNext()) {
			String channelName = items.next().getStringValue();
			String channelId = items.next().getStringValue();
			String address = items.next().getStringValue();
			if (!address.contains(expectedPath)) {
				consumer.consume(new ProcessDirectAddressMatchesIflowNameIssue(
					ruleId, tag, channelName, channelId, address, expectedPath));
			}
		}
	}

}
