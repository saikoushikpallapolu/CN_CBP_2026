// Optional buffer-to-buffer normalization. AVX2 requires a separately enabled
// compiler target; the default scalar loop is portable and auto-vectorizable.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <cstdint>
#if defined(__AVX2__)
#include <immintrin.h>
#endif

static PyObject* normalize(PyObject*, PyObject* args) {
    Py_buffer input{}, output{};
    if (!PyArg_ParseTuple(args, "y*w*", &input, &output)) return nullptr;
    if (output.len != input.len * static_cast<Py_ssize_t>(sizeof(float))) {
        PyBuffer_Release(&input); PyBuffer_Release(&output);
        PyErr_SetString(PyExc_ValueError, "Output must contain one float32 per byte");
        return nullptr;
    }
    auto src = static_cast<const unsigned char*>(input.buf);
    auto dst = static_cast<float*>(output.buf);
    const auto length = input.len;
    Py_BEGIN_ALLOW_THREADS
    Py_ssize_t i = 0;
#if defined(__AVX2__)
    const auto scale = _mm256_set1_ps(1.0f / 127.5f);
    const auto one = _mm256_set1_ps(1.0f);
    for (; i + 8 <= length; i += 8) {
        auto bytes = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(src + i));
        auto value = _mm256_cvtepi32_ps(_mm256_cvtepu8_epi32(bytes));
        _mm256_storeu_ps(dst + i, _mm256_sub_ps(_mm256_mul_ps(value, scale), one));
    }
#endif
    for (; i < length; ++i) dst[i] = src[i] / 127.5f - 1.0f;
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&input); PyBuffer_Release(&output);
    Py_RETURN_NONE;
}
static uint32_t read32(const unsigned char* p, bool little) {
    return little ? uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24
                  : uint32_t(p[3]) | uint32_t(p[2]) << 8 | uint32_t(p[1]) << 16 | uint32_t(p[0]) << 24;
}

static PyObject* read_pcap(PyObject*, PyObject* args) {
    Py_buffer input{};
    Py_ssize_t limit = 200000;
    int truncated = 0;
    if (!PyArg_ParseTuple(args, "y*|np", &input, &limit, &truncated)) return nullptr;
    auto bytes = static_cast<const unsigned char*>(input.buf);
    auto rows = PyList_New(0);
    auto fail = [&](const char* message) -> PyObject* {
        PyBuffer_Release(&input); Py_XDECREF(rows);
        PyErr_SetString(PyExc_ValueError, message); return nullptr;
    };
    if (!rows) {PyBuffer_Release(&input); return nullptr;}
    if (input.len < 24) return fail("Truncated PCAP header");
    bool little = bytes[0] == 0xd4 || bytes[0] == 0x4d;
    const uint32_t magic = read32(bytes, true);
    bool nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
    if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 && !nano) return fail("Invalid classic PCAP magic");
    const double scale = nano ? 1e9 : 1e6;
    const int link = int(read32(bytes + 20, little) & 0xffff);
    Py_ssize_t offset = 24, count = 0;
    while (offset < input.len && count < limit) {
        if (input.len - offset < 16) {
            if (truncated) break;
            return fail("Truncated PCAP record");
        }
        const auto seconds = read32(bytes + offset, little);
        const auto fraction = read32(bytes + offset + 4, little);
        const auto length = read32(bytes + offset + 8, little);
        const auto original = read32(bytes + offset + 12, little);
        if (length > 16 * 1024 * 1024 || length > original) return fail("Invalid PCAP record length");
        offset += 16;
        if (length > uint64_t(input.len - offset)) {
            if (truncated) break;
            return fail("Truncated packet payload");
        }
        auto raw = PyBytes_FromStringAndSize(reinterpret_cast<const char*>(bytes + offset), length);
        if (!raw) {PyBuffer_Release(&input); Py_DECREF(rows); return nullptr;}
        auto row = Py_BuildValue("(dNi)", seconds + fraction / scale, raw, link);
        if (!row || PyList_Append(rows, row) < 0) {
            Py_XDECREF(row); PyBuffer_Release(&input); Py_DECREF(rows); return nullptr;
        }
        Py_DECREF(row);
        offset += length;
        ++count;
    }
    PyBuffer_Release(&input);
    return rows;
}
static PyMethodDef methods[] = {
    {"normalize", normalize, METH_VARARGS, "Normalize uint8 into supplied contiguous float32 buffer."},
    {"read_pcap", read_pcap, METH_VARARGS, "Parse bounded classic PCAP records from a memory-mapped buffer."},
    {nullptr, nullptr, 0, nullptr}};
static PyModuleDef module = {PyModuleDef_HEAD_INIT, "traffic_native", nullptr, -1, methods};
PyMODINIT_FUNC PyInit_traffic_native() {return PyModule_Create(&module);}
