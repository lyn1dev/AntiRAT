package com.antirat.scanner;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Fast, zero-dependency parser that extracts all CONSTANT_Utf8 string literals,
 * class references, method names, and descriptor strings from raw .class bytecode.
 */
public final class ClassConstantPoolReader {

    private static final int MAGIC = 0xCAFEBABE;

    private ClassConstantPoolReader() {
    }

    /**
     * Reads all UTF-8 strings contained in the constant pool of a compiled Java class.
     *
     * @param in input stream containing the raw .class bytes
     * @return list of extracted strings, or an empty list if not a valid class file
     */
    public static List<String> extractUtf8Strings(InputStream in) {
        try {
            DataInputStream dis = new DataInputStream(in);
            int magic = dis.readInt();
            if (magic != MAGIC) {
                return Collections.emptyList();
            }
            int minorVersion = dis.readUnsignedShort();
            int majorVersion = dis.readUnsignedShort();

            int cpCount = dis.readUnsignedShort();
            List<String> strings = new ArrayList<>(Math.max(16, cpCount / 4));

            for (int i = 1; i < cpCount; i++) {
                int tag = dis.readUnsignedByte();
                switch (tag) {
                    case 1: // CONSTANT_Utf8
                        strings.add(dis.readUTF());
                        break;
                    case 3: // CONSTANT_Integer
                    case 4: // CONSTANT_Float
                        dis.skipNBytes(4);
                        break;
                    case 5: // CONSTANT_Long
                    case 6: // CONSTANT_Double
                        dis.skipNBytes(8);
                        i++; // Long and Double consume two constant pool slots in JVM spec
                        break;
                    case 7: // CONSTANT_Class
                    case 8: // CONSTANT_String
                    case 16: // CONSTANT_MethodType
                    case 19: // CONSTANT_Module
                    case 20: // CONSTANT_Package
                        dis.skipNBytes(2);
                        break;
                    case 9: // CONSTANT_Fieldref
                    case 10: // CONSTANT_Methodref
                    case 11: // CONSTANT_InterfaceMethodref
                    case 12: // CONSTANT_NameAndType
                    case 17: // CONSTANT_Dynamic
                    case 18: // CONSTANT_InvokeDynamic
                        dis.skipNBytes(4);
                        break;
                    case 15: // CONSTANT_MethodHandle
                        dis.skipNBytes(3);
                        break;
                    default:
                        // Unknown or invalid tag; return what we parsed so far
                        return strings;
                }
            }
            return strings;
        } catch (IOException | RuntimeException e) {
            return Collections.emptyList();
        }
    }
}
