#pragma once

#include <ostream>
#include <sstream>
#include <test/tools/ossfuzz/abiV2Proto.pb.h>
#include <libdevcore/Whiskers.h>
#include <libdevcore/FixedHash.h>

namespace dev
{
namespace test
{
namespace abiv2fuzzer
{
class ProtoConverter
{
public:
	ProtoConverter()
	{
		m_varIndex = 0;
		m_isStateVar = true;
		m_counter = 0;
	}
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;
	std::string contractToString(Contract const& _input);

private:
	void visit(IntegerType const&);
	void visit(FixedByteType const&);
	void visit(AddressType const&);
	void visit(ArrayType const&);
	void visit(DynamicByteArrayType const&);
	void visit(StructType const&);
	void visit(ValueType const&);
	void visit(NonValueType const&);
	void visit(Type const&);
	void visit(VarDecl const&);
	void visit(TestFunction const&);
	void visit(Contract const&);
	enum class dataLocation
	{
		NONE,
		STORAGE,
		MEMORY,
		CALLDATA
	};

	static std::pair<std::string,std::string> arrayTypeAsString(ArrayType const& _x, bool);
	void appendVarDeclToOutput(std::string _type, std::string _varName, std::string _rhs = {});
	void appendAssignmentToOutput(std::string _varName, std::string _value);
	static std::string structTypeAsString(StructType const& _x);
	static std::string intValueAsString(unsigned _index, unsigned _width);
	static std::string uintValueAsString(unsigned _index, unsigned _width);
	static std::string fixedByteValueAsString(unsigned _index, unsigned _width);
	static inline unsigned getIntWidth(IntegerType const& _x)
	{
		return (8 * ((_x.width() % 32) + 1));
	}
	static inline bool isIntSigned(IntegerType const& _x)
	{
		return _x.is_signed();
	}
	static inline std::string getIntTypeAsString(IntegerType const& _x)
	{
		return ((isIntSigned(_x) ? "int" : "uint") + std::to_string(getIntWidth(_x)));
	}
	std::string integerValueAsString(IntegerType const& _x);
	static std::string addressValueAsString(unsigned _index);
	static inline unsigned getFixedByteWidth(FixedByteType const& _x)
	{
		return ((_x.width() % 32) + 1);
	}
	static inline std::string getFixedByteTypeAsString(FixedByteType const& _x)
	{
		return ("bytes" + std::to_string(getFixedByteWidth(_x)));
	}
	static inline std::string getAddressTypeAsString(AddressType const& _x)
	{
		return (_x.payable() ? "address payable": "address");
	}
	inline unsigned getCounter()
	{
		return m_counter;
	}
	inline void incrementCounter()
	{
		m_counter++;
	}
	inline std::string newVarName()
	{
		return  ("x_" + std::to_string(m_counter));
	}
	inline std::string bytesArrayValueAsString()
	{
		return ("\"" + dev::u256(dev::h256(std::to_string(getCounter()))).str() + "\"");
	}
	static std::string bytesArrayTypeAsString(DynamicByteArrayType const& _x, bool _isStateVariable);

	template <typename T>
	bool isDynamicMemoryArray(T const& _x) const
	{
		return _x.has_array_info() && !m_isStateVar && !_x.array_info().is_static();
	}
	std::string equalityChecksAsString();
	std::string typedParametersAsString(dataLocation _loc);
	void writeHelperFunctions();

	std::string dataLocationToStr(dataLocation _loc);

	std::ostringstream m_output;
	// Holds value of variable under initialization until it is added to the typeLocValue map
	std::string m_currentValue;
	// Holds the current index of variable
	unsigned m_varIndex;
	// Predicate that is true if we are in contract scope
	bool m_isStateVar;
	// Map that maps var index to its type, location, and value. Used by callee functions.
	std::map<unsigned, std::tuple<std::string, bool, std::string>> m_typeLocValueMap;
	unsigned m_counter;
	static unsigned constexpr maxArrayDimensions = 4;
	static unsigned constexpr maxArrayLength = 4;
};
}
}
}