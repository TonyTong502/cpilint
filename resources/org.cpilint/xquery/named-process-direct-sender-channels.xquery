(: Return channel name, ID and address triples, including missing or empty addresses. :)
xquery version "3.1";

declare namespace bpmn2 = "http://www.omg.org/spec/BPMN/20100524/MODEL";
declare namespace ifl = "http:///com.sap.ifl.model/Ifl.xsd";

for $c in //bpmn2:messageFlow[@name = 'ProcessDirect']
where $c/bpmn2:extensionElements/ifl:property[key = 'direction']/value = 'Sender'
return (string($c/@name), string($c/@id), string($c/bpmn2:extensionElements/ifl:property[key = 'address']/value))
