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

if ARGV.length < 1
  print "Please specify a CKL file as an argument.\n"
  print "ruby ckl2csv.rb <file.ckl>\n"
end

# take CKL file as an argument
filename = ARGV[0].to_str
ckl = Nokogiri::XML(File.open(filename))
ckl.remove_namespaces!

# add code to extract filename from input CKL if it has an extension and use to make filename.CSV
output_filename = ""
if filename.index('.')
  output_filename = filename.slice(0..(filename.index('.')-1))
else
  output_filename = filename
end

output = File.new(output_filename+".csv","w")
output << "Vuln ID,Severity,Group Title,Rule ID,Rule Ver,Rule Title,Discussion,IA Control,Check Content,Fix Text,False Positives,False Negatives,Documentable,Mitigations,Potential Impact,Third Party Tools,Mitigation Control,Responsibility,Severity Override Guidance,Check Content Reference,Weight,Classification,STIG Ref,Target Key,CCIs,Status,Finding Details,High,Mod,Low,PII,PHI,CSP-Mod,CSP-Low,Notes,Severity Override,Severity Override Justification\n"

vulns_xpath = "//CHECKLIST/STIGS/iSTIG/VULN"
ckl.xpath(vulns_xpath).each do |node|
  @row = Array.new()
  vuln_num = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Vuln_Num']/ATTRIBUTE_DATA/text()").text
  
  @row << escape_and_prep(vuln_num)
  
  severity = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Severity']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(severity)
  
  group_title = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Group_Title']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(group_title)
    
  rule_id = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Rule_ID']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(rule_id)

  rule_ver = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Rule_Ver']/ATTRIBUTE_DATA/text()").text
  @row << escape_and_prep(rule_ver)

  rule_title = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Rule_Title']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(rule_title)
    
  vuln_discuss = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Vuln_Discuss']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(vuln_discuss)
    
  ia_controls = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='IA_Controls']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(ia_controls)
    
  check_content = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Check_Content']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(check_content)
    
  fix_text = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Fix_Text']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(fix_text)
    
  false_positives = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='False_Positives']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(false_positives)
   
  false_negatives = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='False_Negatives']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(false_negatives)
  
  documentable = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Documentable']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(documentable)

  mitigations = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Mitigations']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(mitigations)
  
  potential_impact = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Potential_Impact']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(potential_impact)
  
  third_party_tools = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Third_Party_Tools']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(third_party_tools)
  
  mitigation_control = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Mitigation_Control']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(mitigation_control)
   
  responsibility = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Responsibility']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(responsibility)
   
  severity_override_guidance = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Security_Override_Guidance']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(severity_override_guidance)
  
  check_content_ref = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Check_Content_Ref']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(check_content_ref)
  
  weight = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Weight']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(weight)
  
  classification = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='Class']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(classification)
  
  stig_ref = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='STIGRef']/ATTRIBUTE_DATA/text()").text 
  @row << escape_and_prep(stig_ref)

  target_key = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='TargetKey']/ATTRIBUTE_DATA/text()").text
  @row << escape_and_prep(target_key)

  @ccis = Array.new()
  cci_node = node.xpath("STIG_DATA[VULN_ATTRIBUTE/text()='CCI_REF']/ATTRIBUTE_DATA")
  cci_node.each do |c|
    @ccis << c
  end
  @row << escape_and_prep(@ccis.join("\n"))

  status = node.xpath("STATUS/text()").text                                                                                                                                          
  @row << escape_and_prep(status)

  finding_details = node.xpath("FINDING_DETAILS/text()").text
  @row << escape_and_prep(finding_details)
 
  comments = node.xpath("COMMENTS/text()").text
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
      print "ERROR: found something that I don't know what it is ("+@ev[0].to_s+").\n"
    end
  end

  severity_override = node.xpath("SEVERITY_OVERRIDE/text()").text
  @row << escape_and_prep(severity_override)

  severity_justification = node.xpath("SEVERITY_JUSTIFICATION/text()").text
  @row << escape_and_prep(severity_justification)

  output << @row.join(",")+"\n"
  
end 
output.close
