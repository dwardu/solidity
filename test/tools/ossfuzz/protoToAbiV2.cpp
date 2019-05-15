#include <test/tools/ossfuzz/protoToAbiV2.h>
#include <libsolidity/codegen/YulUtilFunctions.h>
#include <libdevcore/Whiskers.h>
#include <regex>
#include <liblangutil/Exceptions.h>

using namespace dev::test::abiv2fuzzer;
using namespace std;
using namespace dev::solidity;

/*
 *  Input(s):
 *     - string representation of qualified type T
 *     - optionally, string representation of the right hand side expression
 *  Output(s):
 *     - none
 *  Processing:
 *   - If _rhs is not empty, appends `T x_<index> = <_rhs>;` to converter's output stream
 *     where <index> is string form of `m_varIndex`
 *   - Else appends `T x_<index>;`
 */
void ProtoConverter::appendVarDeclToOutput(std::string _type, std::string _varName, std::string _rhs)
{
	m_output << Whiskers(R"(
	<type> <varName><?isRHS> = <rhs></isRHS>;)"
	)
			("type", _type)
			("varName", _varName)
			("isRHS", !_rhs.empty())
			("rhs", _rhs)
			.render();
}

/*
 *  Input(s):
 *     - variable name (_varName)
 *     - string representation of value being assigned to variable (_value)
 *  Output(s):
 *     - none
 *  Processing:
 *   - Appends `_varName = _value;` to converter's output stream
 */
void ProtoConverter::appendAssignmentToOutput(std::string _varName, std::string _value)
{
	m_output << Whiskers(R"(
	<varName> = <value>;)"
	)
			("varName", _varName)
			("value", _value)
			.render();
}

/* Input(s)
 *   - Unsigned integer to be hashed
 *   - Width of desired uint value
 * Processing
 *   - Take hash of first parameter and mask it with the max unsigned value for given bit width
 * Output
 *   - string representation of uint value
 */
std::string ProtoConverter::uintValueAsString(unsigned _index, unsigned _width)
{
	solAssert((_width % 8 == 0), "Proto ABIv2 Fuzzer: Unsigned integer width is not a multiple of 8");
	/* Mask is used to obtain a value of a type lower than u256
	 * For example, if target type is _width=8 bits, mask equals 0xff
	 * i.e., 0x followed by the character 'f' repeated (_width/4) times
	 */
	dev::u256 mask = dev::u256("0x" + std::string((_width/4), 'f'));
	dev::u256 value = dev::h256(std::to_string(_index)) & mask;
	return value.str();
}

std::string ProtoConverter::addressValueAsString(unsigned _index)
{
	return Whiskers(R"(address(<value>))")
	("value", uintValueAsString(_index, 160))
	.render();
}

std::string ProtoConverter::fixedByteValueAsString(unsigned _index, unsigned _width)
{
	solAssert((_width >= 1 && _width <= 32), "Proto ABIv2 Fuzzer: Fixed byte width is not between 1--32");
	/* Mask is used to obtain a value of a type lower than u256
	 * For example, if target type is _width=1 byte, mask equals 0xff
	 * i.e., 0x followed by the character 'f' repeated (_width*2) times
     */
	dev::u256 mask = dev::u256("0x" + std::string((_width*2), 'f'));
	dev::u256 value = dev::h256(std::to_string(_index)) & mask;
	return value.str();
}

/* Input(s)
 *   - Unsigned integer to be hashed
 *   - Width of desired int value
 * Processing
 *   - Take hash of first parameter and mask it with the max signed value for given bit width
 * Output
 *   - string representation of int value
 */
std::string ProtoConverter::intValueAsString(unsigned _index, unsigned _width)
{
	solAssert((_width % 8 == 0), "Proto ABIv2 Fuzzer: Signed integer width is not a multiple of 8");
	/* Mask is used to obtain a value of a type lower than u256
	 * For example, if target type is _width=8 bits, mask equals 0x7f
	 * i.e., 0x7 followed by the character 'f' repeated (_width/4) - 1 times
	 */
	dev::u256 mask = dev::u256("0x7" + std::string((_width/4 - 1), 'f'));
	dev::u256 value = dev::h256(std::to_string(_index)) & mask;
	return value.str();
}

std::string ProtoConverter::integerValueAsString(IntegerType const& _x)
{
	if (isIntSigned(_x))
		return intValueAsString(getCounter(), getIntWidth(_x));
	return uintValueAsString(getCounter(), getIntWidth(_x));
}

std::string ProtoConverter::bytesArrayTypeAsString(DynamicByteArrayType const& _x, bool _isStateVariable)
{
	switch (_x.type())
	{
	case DynamicByteArrayType::BYTES:
		return (_isStateVariable ? "bytes" : "bytes memory");
	case DynamicByteArrayType::STRING:
		return (_isStateVariable ? "string" : "string memory");
	}
}

std::pair<std::string,std::string> ProtoConverter::arrayTypeAsString(
		ArrayType const&,
		bool
		)
{
//	std::string typeString = typeAsString(_x.basetype());
//	unsigned arrayDimensions = (_x.dimensions() % modArrayDimensions) + 1;
//	unsigned arrayLength = (_x.length() % modArrayLength) + 1;
//	std::string parentheses = {};
//	for (unsigned i = 0; i < arrayDimensions; i++)
//		if (_x.is_static() && i == (arrayDimensions - 1))
//			parentheses += "[" + std::to_string(arrayLength) + "]";
//		else
//			parentheses += "[]";
//
//	// Type
//	std::string qualifiedTypeString = Whiskers(R"(<type><parentheses> <!isState>memory</isState>)")
//			("type", typeString)
//			("parentheses", parentheses)
//			("isState", _isStateVariable)
//			.render();
//
//	// Dynamic memory allocation
//	std::string memAllocationString = {};
//	if (!_x.is_static() && !_isStateVariable)
//		memAllocationString = Whiskers(R"(new <qualType>(<length>))")
//				("qualType", qualifiedTypeString)
//				("length", arrayLength)
//				.render();
//	return std::make_pair(qualifiedTypeString, memAllocationString);
	return std::make_pair("","");
}

std::string ProtoConverter::structTypeAsString(StructType const&)
{
	// TODO: Implement this
	return {};
}

void ProtoConverter::visit(IntegerType const& _x)
{
	appendVarDeclToOutput(
		getIntTypeAsString(_x),
		newVarName(),
		integerValueAsString(_x)
	);
	incrementCounter();
}

void ProtoConverter::visit(AddressType const& _x)
{
	appendVarDeclToOutput(
		getAddressTypeAsString(_x),
		newVarName(),
		addressValueAsString(getCounter())
	);
	incrementCounter();

//	string canonicalType, type;
//	switch (_x.atype())
//	{
//	case AddressType::ADDRESS:
//		canonicalType = "address";
//		type = Whiskers(R"(<?none><type></none><?one><singlearray></one><?many><multiarray></many>)")
//				("none", m_arrayType == arrayType::NONE)
//				("type", canonicalType)
//				("one", m_arrayType == arrayType::ONE)
//				("singlearray", canonicalType + "[]")
//				("many", m_arrayType == arrayType::MANY)
//				("multiarray", "[]")
//				.render();
//		m_varDeclLambda(type);
//		break;
//	case AddressType::PAYABLE:
//		canonicalType = "address payable";
//		type = Whiskers(R"(<?none><type></none><?one><singlearray></one><?many><multiarray></many>)")
//				("none", m_arrayType == arrayType::NONE)
//				("type", canonicalType)
//				("one", m_arrayType == arrayType::ONE)
//				("singlearray", canonicalType + "[]")
//				("many", m_arrayType == arrayType::MANY)
//				("multiarray", "[]")
//				.render();
//		m_varDeclLambda(type);
//		break;
//	}
//	visit(_x.value());
//	m_typeLocValueMap.insert(make_pair(m_varIndex++, make_tuple(type, m_isStateVar, m_currentValue)));
//	m_output << ";\n";
}

void ProtoConverter::visit(ValueType const& _x)
{
	switch (_x.value_type_oneof_case())
	{
		case ValueType::kInty:
			visit(_x.inty());
			break;
		case ValueType::kByty:
			visit(_x.byty());
			break;
		case ValueType::kAdty:
			visit(_x.adty());
			break;
		case ValueType::VALUE_TYPE_ONEOF_NOT_SET:
			break;
	}
}

void ProtoConverter::visit(DynamicByteArrayType const& _x)
{
	appendVarDeclToOutput(
			bytesArrayTypeAsString(_x, m_isStateVar),
			newVarName(),
			bytesArrayValueAsString()
	);
	incrementCounter();
//	m_typeLocValueMap.insert(make_pair(m_varIndex++, make_tuple(type, m_isStateVar, m_currentValue)));
}

// TODO: Implement struct visitor
void ProtoConverter::visit(StructType const&)
{
}

void ProtoConverter::visit(ArrayType const& _x)
{
	switch (_x.base_type_oneof_case())
		case ArrayType::kInty:
		case ArrayType::kByty:
		case ArrayType::kAdty:
		case ArrayType::kStty:
		case ArrayType::BASE_TYPE_ONEOF_NOT_SET:
			break;
}

void ProtoConverter::visit(Type const& _x)
{
	switch (_x.type_oneof_case())
	{
		case Type::kVtype:
			visit(_x.vtype());
			break;
		case Type::kNvtype:
			visit(_x.nvtype());
			break;
		case Type::TYPE_ONEOF_NOT_SET:
			break;
	}
}

void ProtoConverter::visit(VarDecl const& _x)
{
	visit(_x.type());
}

void ProtoConverter::visit(FixedByteType const& _x)
{
	appendVarDeclToOutput(
		getFixedByteTypeAsString(_x),
		newVarName(),
		fixedByteValueAsString(getCounter(), getFixedByteWidth(_x))
	);
	incrementCounter();
}

// Called by g()
std::string ProtoConverter::equalityChecksAsString()
{
	ostringstream out;

	for (auto const& kv: m_typeLocValueMap)
	{
		if (get<0>(kv.second) == "string" || get<0>(kv.second) == "string memory")
				out << Whiskers(R"(
		if (!stringCompare(g_<i>, <value>)) return false;
				)")
				("i", std::to_string(kv.first))
				("value", get<2>(kv.second))
				.render();
		else if (get<0>(kv.second) == "bytes" || get<0>(kv.second) == "bytes memory")
				out << Whiskers(R"(
		if (!bytesCompare(g_<i>, <value>)) return false;
				)")
				("i", std::to_string(kv.first))
				("value", get<2>(kv.second))
				.render();
		else
				out << Whiskers(R"(
		if (g_<i> != <value>) return false;
				)")
				("i", std::to_string(kv.first))
				("value", get<2>(kv.second))
				.render();
	}
	return out.str();
}

std::string ProtoConverter::dataLocationToStr(dataLocation _loc)
{
	switch (_loc)
	{
	case dataLocation::STORAGE:
		return "storage";
	case dataLocation::MEMORY:
		return "memory";
	case dataLocation::CALLDATA:
		return "calldata";
	case dataLocation::NONE:
		solAssert(false, "Proto ABIV2 fuzzer: Invalid data location.");
	}
}

std::string ProtoConverter::typedParametersAsString(dataLocation _loc)
{
	ostringstream out;
	// FIXME: Don't depend on size of m_typeLocValueMap == m_varIndex
	solAssert(m_typeLocValueMap.size() == m_varIndex, "ABIv2 proto fuzzer: Mismatch between map size and var index");
	for (auto const& kv : m_typeLocValueMap)
	{
		if (get<0>(kv.second) == "bytes" || get<0>(kv.second) == "string")
			out << Whiskers(R"(<type> <location> g_<i><delimiter>)")
			("type", get<0>(kv.second))
			("location", dataLocationToStr(_loc))
			("i", std::to_string(kv.first))
			("delimiter", (kv.first == (m_varIndex - 1) ? "" : ", "))
			.render();
		else if (get<0>(kv.second) == "bytes memory" || get<0>(kv.second) == "string memory")
			out << Whiskers(R"(<?calldata><calldata_type><!calldata><memory_type></calldata> g_<i><delimiter>)")
					("calldata", (_loc == dataLocation::CALLDATA))
					("calldata_type", std::regex_replace(get<0>(kv.second), std::regex("memory"), std::string("calldata")))
					("memory_type", get<0>(kv.second))
					("i", std::to_string(kv.first))
					("delimiter", (kv.first == (m_varIndex - 1) ? "" : ", "))
					.render();
		else
			out << Whiskers(R"(<type> g_<i><delimiter>)")
			("type", get<0>(kv.second))
			("i", std::to_string(kv.first))
			("delimiter", (kv.first == (m_varIndex - 1) ? "" : ", "))
			.render();
	}
	return out.str();
}

// Caller function
void ProtoConverter::visit(TestFunction const& _x)
{
	m_output << Whiskers(R"(
	function f() public returns (bool) {
	)")
	.render();

	// TODO: Support more than one but less than N local variables
	visit(_x.local_vars());

	m_output << Whiskers(R"(
		return (this.g_public(<parameter_names>) && this.g_external(<parameter_names>));
	}
	)")
	("parameter_names", YulUtilFunctions::suffixedVariableNameList("x_", 0, m_varIndex))
	.render();
}

void ProtoConverter::writeHelperFunctions()
{
	m_output << Whiskers(R"(
	function stringCompare(string memory a, string memory b) internal pure returns (bool) {
		if(bytes(a).length != bytes(b).length)
			return false;
		else
			return keccak256(bytes(a)) == keccak256(bytes(b));
	}
	)").render();

	m_output << Whiskers(R"(
	function bytesCompare(bytes memory a, bytes memory b) internal pure returns (bool) {
		if(a.length != b.length)
			return false;
		for (uint i = 0; i < a.length; i++)
			if (a[i] != b[i])
				return false;
		return true;
	}
	)").render();

//	auto arrayCompare = [](auto type) {
//		return Whiskers(R"(
//	function arrayCompare(<type>[] memory a, <type>[] memory b) internal pure returns (bool) {
//		if (a.length != b.length)
//			return false;
//		else
//			return keccak256(abi.encode(a)) == keccak256(abi.encode(b));
//	}
//	)")
//		("type", type)
//		.render();
//	};

	// These are callee functions that encode from storage, decode to
	// memory/calldata and check if decoded value matches storage value
	// return true on successful match, false otherwise
	m_output << Whiskers(R"(
	function g_public(<parameters_memory>) public view returns (bool) {
		<equality_checks>
		return true;
	}

	function g_external(<parameters_calldata>) external view returns (bool) {
		<equality_checks>
		return true;
	}
	)"
	)
	("parameters_memory", typedParametersAsString(dataLocation::MEMORY))
	("equality_checks", equalityChecksAsString())
	("parameters_calldata", typedParametersAsString(dataLocation::CALLDATA))
	.render();
}

void ProtoConverter::visit(Contract const& _x)
{
	m_output << Whiskers(R"(pragma solidity >=0.0;
pragma experimental ABIEncoderV2;

contract C {
)").render();
	// TODO: Support more than one but less than N state variables
	visit(_x.state_vars());
	m_isStateVar = false;
	// Test function
	visit(_x.testfunction());
	writeHelperFunctions();
	m_output << "\n}";
}

string ProtoConverter::contractToString(Contract const& _input)
{
	visit(_input);
	return m_output.str();
}