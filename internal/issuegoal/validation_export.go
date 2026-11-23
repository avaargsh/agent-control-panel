package issuegoal

// ValidateTargetBranch exposes the same canonical Git reference validator
// used by the offline manifest. This is not a remote existence check.
func ValidateTargetBranch(branch string) error {
	if !validBranch(branch) {
		return ErrInvalidGoal
	}
	return nil
}
