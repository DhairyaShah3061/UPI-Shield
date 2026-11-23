package com.upishield.riskengine.rules;

import com.upishield.riskengine.dto.RiskIndicator;

public interface RiskRule {

    String getRuleId();

    RiskIndicator evaluate(RiskContext context);
}
