package es.in2.issuer.infrastructure.iam.util;

import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Objects;

public class IamSourceNameCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context, @NotNull AnnotatedTypeMetadata metadata) {
        String expectedImplementation = context.getEnvironment().getProperty("app.iam-source.name");
        if (expectedImplementation != null) {
            try {
                String actualImplementation = Objects.requireNonNull(metadata.getAnnotationAttributes(IamSourceName.class.getName())).get("name").toString();
                return expectedImplementation.equals(actualImplementation);
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

}
