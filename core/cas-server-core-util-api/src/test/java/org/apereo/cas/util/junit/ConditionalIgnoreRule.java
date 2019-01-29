package org.apereo.cas.util.junit;

import lombok.val;
import org.junit.Assume;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import java.lang.reflect.Modifier;

/**
 * This is {@link ConditionalIgnoreRule}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 * @deprecated Not needed with Junit5
 */
@Deprecated
public class ConditionalIgnoreRule implements TestRule {
    /**
     * Has conditional ignore annotation boolean.
     *
     * @param target the target
     * @return the boolean
     */
    private static boolean hasConditionalIgnoreAnnotation(final Description target) {
        return target.getTestClass().isAnnotationPresent(ConditionalIgnore.class) || target.getAnnotation(ConditionalIgnore.class) != null;
    }

    /**
     * Gets ignore condition.
     *
     * @param target the target
     * @return the ignore condition
     */
    private static IgnoreCondition getIgnoreCondition(final Description target) {
        var annotation = target.getAnnotation(ConditionalIgnore.class);
        if (annotation == null) {
            annotation = target.getTestClass().getAnnotation(ConditionalIgnore.class);
        }
        return new IgnoreConditionCreator(target, annotation).create();
    }

    @Override
    public Statement apply(final Statement base, final Description target) {
        if (hasConditionalIgnoreAnnotation(target)) {
            val condition = getIgnoreCondition(target);
            if (!condition.isSatisfied()) {
                return new IgnoreStatement(condition);
            }
        }
        return base;
    }

    /**
     * The type Ignore condition creator.
     */
    private static class IgnoreConditionCreator {
        private final Description target;
        private final Class<? extends IgnoreCondition> conditionType;

        /**
         * Instantiates a new Ignore condition creator.
         *
         * @param target     the target
         * @param annotation the annotation
         */
        IgnoreConditionCreator(final Description target, final ConditionalIgnore annotation) {
            this.target = target;
            this.conditionType = annotation.condition();
        }

        /**
         * Create ignore condition.
         *
         * @return the ignore condition
         */
        IgnoreCondition create() {
            checkConditionType();
            try {
                return createCondition();
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * Create condition ignore condition.
         *
         * @return the ignore condition
         * @throws Exception the exception
         */
        private IgnoreCondition createCondition() throws Exception {
            if (isConditionTypeStandalone()) {
                return conditionType.getDeclaredConstructor().newInstance();
            }
            return conditionType.getDeclaredConstructor(target.getClass()).newInstance(target);
        }

        /**
         * Check condition type.
         */
        private void checkConditionType() {
            if (!isConditionTypeStandalone() && !isConditionTypeDeclaredInTarget()) {
                val msg
                    = "Conditional class '%s' is a member class "
                    + "but was not declared inside the test case using it.\n"
                    + "Either make this class a static class, "
                    + "standalone class (by declaring it in it's own file) "
                    + "or move it inside the test case using it";
                throw new IllegalArgumentException(String.format(msg, conditionType.getName()));
            }
        }

        /**
         * Is condition type standalone boolean.
         *
         * @return the boolean
         */
        private boolean isConditionTypeStandalone() {
            return !conditionType.isMemberClass() || Modifier.isStatic(conditionType.getModifiers());
        }

        /**
         * Is condition type declared in target boolean.
         *
         * @return the boolean
         */
        private boolean isConditionTypeDeclaredInTarget() {
            return target.getClass().isAssignableFrom(conditionType.getDeclaringClass());
        }
    }

    /**
     * The type Ignore statement.
     */
    public static class IgnoreStatement extends Statement {
        private final IgnoreCondition condition;

        /**
         * Instantiates a new Ignore statement.
         *
         * @param condition the condition
         */
        IgnoreStatement(final IgnoreCondition condition) {
            this.condition = condition;
        }

        @Override
        public void evaluate() {
            Assume.assumeTrue("Ignored by " + condition.getClass().getSimpleName(), false);
        }
    }

}

