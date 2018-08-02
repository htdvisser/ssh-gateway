package forward

import "context"

type environmentKeyType struct{}

var environmentKey environmentKeyType

type environment map[string]string

// NewContextWithEnvironment returns a contet with the merged environment
func NewContextWithEnvironment(ctx context.Context, toAdd map[string]string) context.Context {
	env := make(environment)
	for k, v := range EnvironmentFromContext(ctx) {
		env[k] = v
	}
	for k, v := range toAdd {
		env[k] = v
	}
	return context.WithValue(ctx, environmentKey, env)
}

// EnvironmentFromContext returns the environment from the context.
func EnvironmentFromContext(ctx context.Context) map[string]string {
	env, ok := ctx.Value(environmentKey).(environment)
	if !ok || env == nil {
		env = make(environment)
	}
	return env
}
