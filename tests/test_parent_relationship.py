"""Tests for RootFS layer relationship verification.

The clean parent image may only be adopted when its ordered layer chain is
provably a prefix of the runtime image's chain. Tag naming and env.sh agreement
are candidate discovery signals, never proof.
"""

import pytest

from docker_migration_tool.inspect.image import verify_layer_relationship
from docker_migration_tool.model import ImageInfo, LayerRelationship


L1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
L2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
L3 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
L4 = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
L5 = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
LX = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"


class TestVerifyLayerRelationship:
    """Layer chain comparison."""

    def test_exact_prefix_is_verified(self):
        """A clean parent whose chain is an exact prefix is accepted."""
        result, reason = verify_layer_relationship(
            [L1, L2, L3, L4, L5], [L1, L2, L3]
        )
        assert result is LayerRelationship.STRICT_PREFIX
        assert "prefix" in reason

    def test_non_prefix_is_rejected(self):
        """[L1,L2,L3,X] is not a parent of [L1,L2,L3,L4,L5]."""
        result, reason = verify_layer_relationship(
            [L1, L2, L3, L4, L5], [L1, L2, L3, LX]
        )
        assert result is LayerRelationship.NOT_PREFIX
        assert "diverges" in reason

    def test_candidate_longer_than_runtime_is_rejected(self):
        """A candidate with more layers is a descendant, not a parent."""
        result, reason = verify_layer_relationship(
            [L1, L2, L3], [L1, L2, L3, L4]
        )
        assert result is LayerRelationship.CANDIDATE_LONGER
        assert "more layers" in reason

    def test_identical_chains_are_verified(self):
        """runtime image == clean image (never committed) still works."""
        result, reason = verify_layer_relationship(
            [L1, L2, L3], [L1, L2, L3]
        )
        assert result is LayerRelationship.IDENTICAL
        assert "already clean" in reason

    def test_missing_layer_data_is_rejected(self):
        """No .RootFS.Layers means nothing can be proven."""
        result, _ = verify_layer_relationship([L1, L2], [])
        assert result is LayerRelationship.MISSING_LAYER_DATA

        result, _ = verify_layer_relationship([], [L1])
        assert result is LayerRelationship.MISSING_LAYER_DATA

    def test_order_matters(self):
        """The same layers in a different order are not a prefix."""
        result, _ = verify_layer_relationship([L1, L2, L3], [L2, L1])
        assert result is LayerRelationship.NOT_PREFIX

    def test_single_extra_layer_snapshot_case(self):
        """The real case: a commit snapshot adds exactly one layer."""
        parent = [L1, L2, L3, L4]
        snapshot = parent + [L5]
        result, _ = verify_layer_relationship(snapshot, parent)
        assert result is LayerRelationship.STRICT_PREFIX


class TestResolveCleanParentImage:
    """End-to-end candidate resolution with docker calls stubbed out."""

    @staticmethod
    def _runtime(is_snapshot: bool, layers: list[str]) -> ImageInfo:
        return ImageInfo(
            repository="example/workspace",
            tag="ws-snapshot-0001" if is_snapshot else "ws-base",
            image_id="deadbeef1234",
            layer_count=len(layers),
            is_snapshot=is_snapshot,
            rootfs_layers=layers,
        )

    @pytest.fixture
    def patched(self, monkeypatch):
        """Stub candidate discovery and layer lookups."""
        from docker_migration_tool.inspect import image as image_module

        state: dict = {"candidates": [], "layers": {}, "infos": {}}

        def fake_discover(runtime_info, env_sh_path=None):
            return state["candidates"]

        def fake_layers(references):
            return {ref: state["layers"][ref]
                    for ref in references if ref in state["layers"]}

        def fake_inspect(image):
            return state["infos"][image]

        monkeypatch.setattr(image_module, "discover_clean_parent_candidates",
                            fake_discover)
        monkeypatch.setattr(image_module, "get_images_rootfs_layers", fake_layers)
        monkeypatch.setattr(image_module, "inspect_image", fake_inspect)
        return state

    def test_prefix_candidate_is_adopted(self, patched):
        from docker_migration_tool.inspect.image import resolve_clean_parent_image

        runtime = self._runtime(True, [L1, L2, L3, L4, L5])
        parent_ref = "example/workspace:base"
        patched["candidates"] = [(parent_ref, "env.sh")]
        patched["layers"] = {parent_ref: [L1, L2, L3, L4]}
        patched["infos"] = {
            parent_ref: ImageInfo(
                repository="example/workspace", tag="base",
                image_id="cafe12345678", layer_count=4,
                rootfs_layers=[L1, L2, L3, L4],
            )
        }

        parent, relationship = resolve_clean_parent_image(
            "runtime", runtime_info=runtime
        )

        assert parent is not None
        assert parent.is_clean_parent is True
        assert relationship.verified is True
        assert relationship.relationship == "strict_prefix"
        assert relationship.runtime_layer_count == 5
        assert relationship.candidate_layer_count == 4
        assert relationship.candidate_source == "env.sh"

    def test_same_tag_suffix_but_wrong_chain_is_rejected(self, patched):
        """A decoy with a matching tag but a diverging chain is refused."""
        from docker_migration_tool.inspect.image import resolve_clean_parent_image

        runtime = self._runtime(True, [L1, L2, L3, L4, L5])
        decoy = "personal/workspace:base"
        patched["candidates"] = [(decoy, "repository tag naming")]
        patched["layers"] = {decoy: [L1, L2, LX, L4]}
        patched["infos"] = {}

        parent, relationship = resolve_clean_parent_image(
            "runtime", runtime_info=runtime
        )

        assert parent is None
        assert relationship.verified is False
        assert len(relationship.rejected_candidates) == 1
        assert relationship.rejected_candidates[0]["image"] == decoy
        assert relationship.rejected_candidates[0]["relationship"] == "not_prefix"

    def test_snapshot_never_selects_itself(self, patched):
        """An identical chain is refused while the runtime image is a snapshot."""
        from docker_migration_tool.inspect.image import resolve_clean_parent_image

        runtime = self._runtime(True, [L1, L2, L3])
        patched["candidates"] = [(runtime.reference, "runtime image itself")]
        patched["layers"] = {runtime.reference: [L1, L2, L3]}
        patched["infos"] = {}

        parent, relationship = resolve_clean_parent_image(
            "runtime", runtime_info=runtime
        )

        assert parent is None
        assert relationship.rejected_candidates[0]["relationship"] == "snapshot_itself"

    def test_already_clean_runtime_image_is_accepted(self, patched):
        """runtime image is already clean -> identical chain is adopted."""
        from docker_migration_tool.inspect.image import resolve_clean_parent_image

        runtime = self._runtime(False, [L1, L2, L3])
        patched["candidates"] = [(runtime.reference, "runtime image itself")]
        patched["layers"] = {runtime.reference: [L1, L2, L3]}
        patched["infos"] = {runtime.reference: runtime}

        parent, relationship = resolve_clean_parent_image(
            "runtime", runtime_info=runtime
        )

        assert parent is not None
        assert relationship.verified is True
        assert relationship.relationship == "identical"
        assert relationship.candidate_layer_count == 3

    def test_closest_verified_ancestor_is_preferred(self, patched):
        """Grandparents also verify; the nearest ancestor must win."""
        from docker_migration_tool.inspect.image import resolve_clean_parent_image

        runtime = self._runtime(True, [L1, L2, L3, L4, L5])
        grandparent = "nvidia/cuda:12.8.1-cudnn-devel-ubuntu22.04"
        parent_ref = "example/workspace:base"
        patched["candidates"] = [
            (grandparent, "local image layer-chain search"),
            (parent_ref, "env.sh"),
        ]
        patched["layers"] = {
            grandparent: [L1, L2],
            parent_ref: [L1, L2, L3, L4],
        }
        patched["infos"] = {
            grandparent: ImageInfo(repository="nvidia/cuda", tag="12.8.1",
                                   image_id="aaa", layer_count=2,
                                   rootfs_layers=[L1, L2]),
            parent_ref: ImageInfo(repository="example/workspace", tag="base",
                                  image_id="bbb", layer_count=4,
                                  rootfs_layers=[L1, L2, L3, L4]),
        }

        parent, relationship = resolve_clean_parent_image(
            "runtime", runtime_info=runtime
        )

        assert parent is not None
        assert relationship.candidate_image == parent_ref
        assert relationship.candidate_layer_count == 4
