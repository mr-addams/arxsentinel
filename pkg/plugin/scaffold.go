// ========================== pkg/plugin — NopManifest scaffold ===========================
//   Temporary scaffold — embed NopManifest in plugin structs while
//   real Manifest() is not yet implemented. Remove embedding after adding real Manifest().

package plugin

// NopManifest provides a no-op Manifest() method for plugin structs.
// Embed NopManifest to satisfy the Manifest() requirement temporarily.
type NopManifest struct{}

// Manifest returns an empty Manifest.
func (NopManifest) Manifest() Manifest { return Manifest{} }