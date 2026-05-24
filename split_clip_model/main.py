import onnx
from onnx.utils import Extractor

SRC = "models/jina-clip-v2/onnx/model.onnx"

model = onnx.load(SRC, load_external_data=True)

extractor = Extractor(model)

# ---------- Text ----------
text_model = extractor.extract_model(
    input_names=["input_ids"],
    output_names=["l2norm_text_embeddings"],
)
onnx.save_model(
    text_model,
    "models/jina-clip-v2/onnx/jina-clip-v2-text.onnx",
    save_as_external_data=True,
    all_tensors_to_one_file=True,
    location="jina-clip-v2-text.onnx_data",
    size_threshold=1024,
)

# ---------- Vision ----------
vision_model = extractor.extract_model(
    input_names=["pixel_values"],
    output_names=["l2norm_image_embeddings"],
)
onnx.save_model(
    vision_model,
    "models/jina-clip-v2/onnx/jina-clip-v2-vision.onnx",
    save_as_external_data=True,
    all_tensors_to_one_file=True,
    location="jina-clip-v2-vision.onnx_data",
    size_threshold=1024,
)

onnx.checker.check_model("models/jina-clip-v2/onnx/jina-clip-v2-text.onnx")
onnx.checker.check_model("models/jina-clip-v2/onnx/jina-clip-v2-vision.onnx")
print("✅ Done")
