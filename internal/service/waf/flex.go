package waf

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func ExpandAction(l []interface{}) *waf.WafAction {
	if len(l) == 0 || l[0] == nil {
		return nil
	}

	m := l[0].(map[string]interface{})

	return &waf.WafAction{
		Type: aws.String(m["type"].(string)),
	}
}

func FlattenAction(n *waf.WafAction) []map[string]interface{} {
	if n == nil {
		return nil
	}

	result := map[string]interface{}{
		"type": aws.StringValue(n.Type),
	}

	return []map[string]interface{}{result}
}

func expandOverrideAction(l []interface{}) *waf.WafOverrideAction {
	if len(l) == 0 || l[0] == nil {
		return nil
	}

	m := l[0].(map[string]interface{})

	return &waf.WafOverrideAction{
		Type: aws.String(m["type"].(string)),
	}
}

func ExpandWebACLUpdate(updateAction string, aclRule map[string]interface{}) *waf.WebACLUpdate {
	var rule *waf.ActivatedRule

	switch aclRule["type"].(string) {
	case waf.WafRuleTypeGroup:
		rule = &waf.ActivatedRule{
			OverrideAction: expandOverrideAction(aclRule["override_action"].([]interface{})),
			Priority:       aws.Int64(int64(aclRule["priority"].(int))),
			RuleId:         aws.String(aclRule["rule_id"].(string)),
			Type:           aws.String(aclRule["type"].(string)),
		}
	default:
		rule = &waf.ActivatedRule{
			Action:   ExpandAction(aclRule["action"].([]interface{})),
			Priority: aws.Int64(int64(aclRule["priority"].(int))),
			RuleId:   aws.String(aclRule["rule_id"].(string)),
			Type:     aws.String(aclRule["type"].(string)),
		}
	}

	update := &waf.WebACLUpdate{
		Action:        aws.String(updateAction),
		ActivatedRule: rule,
	}

	return update
}

func FlattenWebACLRules(ts []*waf.ActivatedRule) []map[string]interface{} {
	out := make([]map[string]interface{}, len(ts))
	for i, r := range ts {
		m := make(map[string]interface{})

		switch aws.StringValue(r.Type) {
		case waf.WafRuleTypeGroup:
			actionMap := map[string]interface{}{
				"type": aws.StringValue(r.OverrideAction.Type),
			}
			m["override_action"] = []map[string]interface{}{actionMap}
		default:
			actionMap := map[string]interface{}{
				"type": aws.StringValue(r.Action.Type),
			}
			m["action"] = []map[string]interface{}{actionMap}
		}

		m["priority"] = int(aws.Int64Value(r.Priority))
		m["rule_id"] = aws.StringValue(r.RuleId)
		m["type"] = aws.StringValue(r.Type)
		out[i] = m
	}
	return out
}

func ExpandFieldToMatch(d map[string]interface{}) *waf.FieldToMatch {
	ftm := &waf.FieldToMatch{
		Type: aws.String(d["type"].(string)),
	}
	if data, ok := d["data"].(string); ok && data != "" {
		ftm.Data = aws.String(data)
	}
	return ftm
}

func FlattenFieldToMatch(fm *waf.FieldToMatch) []interface{} {
	m := make(map[string]interface{})
	if fm.Data != nil {
		m["data"] = aws.StringValue(fm.Data)
	}
	if fm.Type != nil {
		m["type"] = aws.StringValue(fm.Type)
	}
	return []interface{}{m}
}

func FlattenRedactedFields(fieldToMatches []*waf.FieldToMatch) []interface{} {
	if len(fieldToMatches) == 0 {
		return []interface{}{}
	}

	fieldToMatchResource := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"data": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
	l := make([]interface{}, len(fieldToMatches))

	for i, fieldToMatch := range fieldToMatches {
		l[i] = FlattenFieldToMatch(fieldToMatch)[0]
	}

	m := map[string]interface{}{
		"field_to_match": schema.NewSet(schema.HashResource(fieldToMatchResource), l),
	}

	return []interface{}{m}
}

func ExpandLoggingConfiguration(l []interface{}, resourceARN string) *waf.LoggingConfiguration {
	if len(l) == 0 || l[0] == nil {
		return nil
	}

	m := l[0].(map[string]interface{})

	loggingConfiguration := &waf.LoggingConfiguration{
		LogDestinationConfigs: []*string{
			aws.String(m["log_destination"].(string)),
		},
		RedactedFields: ExpandRedactedFields(m["redacted_fields"].([]interface{})),
		ResourceArn:    aws.String(resourceARN),
	}

	return loggingConfiguration
}

func FlattenLoggingConfiguration(loggingConfiguration *waf.LoggingConfiguration) []interface{} {
	if loggingConfiguration == nil {
		return []interface{}{}
	}

	m := map[string]interface{}{
		"log_destination": "",
		"redacted_fields": FlattenRedactedFields(loggingConfiguration.RedactedFields),
	}

	if len(loggingConfiguration.LogDestinationConfigs) > 0 {
		m["log_destination"] = aws.StringValue(loggingConfiguration.LogDestinationConfigs[0])
	}

	return []interface{}{m}
}

func ExpandRedactedFields(l []interface{}) []*waf.FieldToMatch {
	if len(l) == 0 || l[0] == nil {
		return nil
	}

	m := l[0].(map[string]interface{})

	if m["field_to_match"] == nil {
		return nil
	}

	redactedFields := make([]*waf.FieldToMatch, 0)

	for _, fieldToMatch := range m["field_to_match"].(*schema.Set).List() {
		if fieldToMatch == nil {
			continue
		}

		redactedFields = append(redactedFields, ExpandFieldToMatch(fieldToMatch.(map[string]interface{})))
	}

	return redactedFields
}
