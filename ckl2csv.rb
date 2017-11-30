#!/usr/local/bin/ruby

require 'nokogiri'
require 'optparse'
require 'fileutils'

def get_value(ev)
  if @ev[1] == " DELTA" || @ev[1] == "DELTA"
    return @ev[2]
  else
    return @ev[1]
  end
end

def escape_and_prep(str)
  # escape "'s
  mstr = str.gsub("\"","\"\"")
  # prep by enclosing string in "'s
  mstr = "\""+mstr+"\""
  return mstr
end

ckl = Nokogiri::XML(File.open("rhel7-clean.ckl"))
ckl.remove_namespaces!
output = File.new("output.csv","w")
output << "Vuln ID,Severity,Group Title,Rule ID,STIG ID,Rule Title,Discussion,IA Control,Check Content,Fix Text,False Positives,False Negatives,Documentable,Mitigations,Potential Impact,Third Party Tools,Mitigation Control,Responsibility,Severity Override Guidance,Check Content Reference,Weight,Classification,STIG,Target Key,CCIs,Status,Finding Details,High,Mod,Low,PII,PHI,CSP-Mod,CSP-Low,Notes,Severity Override,Severity Override Justification\n"

vulns_xpath = "//CHECKLIST/STIGS/iSTIG/VULN"
ckl.xpath(vulns_xpath).each do |node|
  @row = Array.new()
  vuln_num = node.xpath("./STIG_DATA[1]/ATTRIBUTE_DATA/text()").text 	
  @row << escape_and_prep(vuln_num)
  
  severity = node.xpath("./STIG_DATA[2]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(severity)
  
  group_title = node.xpath("./STIG_DATA[3]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(group_title)
    
  rule_id = node.xpath("./STIG_DATA[4]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(rule_id)

  stig_id = node.xpath("./STIG_DATA[5]/ATTRIBUTE_DATA/text()").text
  @row << escape_and_prep(stig_id)

  rule_title = node.xpath("./STIG_DATA[6]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(rule_title)
    
  vuln_discuss = node.xpath("./STIG_DATA[7]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(vuln_discuss)
    
  ia_controls = node.xpath("./STIG_DATA[8]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(ia_controls)
    
  check_content = node.xpath("./STIG_DATA[9]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(check_content)
    
  fix_text = node.xpath("./STIG_DATA[10]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(fix_text)
    
  false_positives = node.xpath("./STIG_DATA[11]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(false_positives)
   
  false_negatives = node.xpath("./STIG_DATA[12]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(false_negatives)
  
  documentable = node.xpath("./STIG_DATA[13]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(documentable)

  mitigations = node.xpath("./STIG_DATA[14]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(mitigations)
  
  potential_impact = node.xpath("./STIG_DATA[15]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(potential_impact)
  
  third_party_tools = node.xpath("./STIG_DATA[16]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(third_party_tools)
  
  mitigation_control = node.xpath("./STIG_DATA[17]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(mitigation_control)
   
  responsibility = node.xpath("./STIG_DATA[18]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(responsibility)
   
  severity_override_guidance = node.xpath("./STIG_DATA[19]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(severity_override_guidance)
  
  check_content_ref = node.xpath("./STIG_DATA[20]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(check_content_ref)
  
  weight = node.xpath("./STIG_DATA[21]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(weight)
  
  classification = node.xpath("./STIG_DATA[22]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(classification)
  
  stig_ref = node.xpath("./STIG_DATA[23]/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(stig_ref)

  target_key = node.xpath("./STIG_DATA[24]/ATTRIBUTE_DATA/text()").text
  @row << escape_and_prep(target_key)

  @ccis = Array.new()
  node.xpath("./STIG_DATA/VULN_ATTRIBUTE[text()='CCI_REF']/following::ATTRIBUTE_DATA[1]/text()").each do |c|
    @ccis << c
  end
  @row << escape_and_prep(@ccis.join("\n"))

  status = node.xpath("./STATUS/text()").text                                                                                                                                          
  @row << escape_and_prep(status)

  finding_details = node.xpath("./FINDING_DETAILS/text()").text
  @row << escape_and_prep(finding_details)
 
  comments = node.xpath("./COMMENTS/text()").text
  @comments_array = comments.split("\n") 
  @comments_array.each do |e|
    @ev = e.split(",")
    if @ev[0] == "HIGH"
      @row << get_value(@ev)
    elsif @ev[0] == "MOD"
      @row << get_value(@ev)
    elsif @ev[0] == "LOW"
      @row << get_value(@ev)
    elsif @ev[0] == "PII"
      @row << get_value(@ev)
    elsif @ev[0] == "PHI"
      @row << get_value(@ev)
    elsif @ev[0] == "CSP-MOD"
      @row << get_value(@ev)
    elsif @ev[0] == "CSP-LOW"
      @row << get_value(@ev)
    elsif @ev[0] == "NOTES"
      @ev.delete_at(0)
      @row << @ev.join(",")
    else
      print "ERROR: found something that I don't know what it is ("+@ev[0]+").\n"
    end
  end

  severity_override = node.xpath("./SEVERITY_OVERRIDE/text()").text
  @row << escape_and_prep(severity_override)

  severity_justification = node.xpath("./SEVERITY_JUSTIFICATION/text()").text
  @row << escape_and_prep(severity_justification)

  output << @row.join(",")+"\n"
  
end 
output.close
