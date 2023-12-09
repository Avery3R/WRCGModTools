#include <iostream>
#include <fstream>
#include <filesystem>
#include <span>
#include <vector>
#define OPENSSL_API_COMPAT 1110
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <lz4frame.h>

#pragma pack(push, 1)
struct PPKGHeader
{
	char magic[4];
	uint32_t version;
	uint32_t unk;
	uint32_t fileHeadersSize;
	uint8_t reserved[0x20];
};
static_assert(sizeof(PPKGHeader) == 0x30, "sizeof(PPKGHeader) == 0x30");
#pragma pack(pop)

enum FileCompressionType : uint32_t
{
	FCT_None = 0,
	FCT_Unk1 = 1,
	FCT_LZ4F = 2,
};

struct FileMetadata
{
	std::string fileName;
	uint32_t checksum;
	uint64_t filetime;
	uint64_t dataOffset;
	uint64_t rawDataSize;
	uint64_t uncompressedDataSize;
	FileCompressionType compressionType;
};

enum GameGeneration
{
	GG_UNKNOWN = 0,
	GG_WRC9,
	GG_WRC10,
	GG_WRCG
};

const std::string DEFAULT_XOR_KEY = "14F5FsyDFFUC4NVANPpYggyakreWkJfy";

inline void XorData(const std::string_view xorKey, std::span<uint8_t> data, size_t keyOffset = 0)
{
	for (size_t i = 0; i < data.size(); ++i)
	{
		data[i] ^= xorKey[(i+keyOffset)%xorKey.size()];
	}
}

int main(int argc, char** argv)
{
	const auto basePath = std::filesystem::current_path();

	GameGeneration gameGeneration = GG_UNKNOWN;

	if(std::filesystem::exists(basePath / "WRCG.exe"))
	{
		gameGeneration = GG_WRCG;
	}
	else if(std::filesystem::exists(basePath / "WRC10.exe"))
	{
		gameGeneration = GG_WRC10;
	}
	else if(std::filesystem::exists(basePath / "WRC9.exe"))
	{
		gameGeneration = GG_WRC9;
	}
	else
	{
		std::cerr << "Unpackager must be run from within the same folder as the game's main exe file (WRCG.exe/WRC10.exe/WRC9.exe)\n" << "Press enter to exit..." << std::endl;
		std::cin.ignore(99999, '\n');
		return 1;
	}

	if(gameGeneration != GG_WRCG)
	{
		std::cout << "Warning: Support for versions other than WRCG is experimental and may not work correctly. Use as your own risk" << std::endl;
	}

	const auto pkgsFolder = basePath / "WIN32" / "PKG";

	std::vector<std::filesystem::path> pkgFiles;

	for(const auto &pkgChunkFolder : std::filesystem::directory_iterator(pkgsFolder))
	{
		if(std::filesystem::is_directory(pkgChunkFolder))
		{
			for(const auto &pkgFile : std::filesystem::directory_iterator(pkgChunkFolder))
			{
				if(pkgFile.path().extension() == ".PKG")
				{
					pkgFiles.push_back(pkgFile.path());
				}
			}
		}
	}

	for(size_t pkgIndex = 0; pkgIndex < pkgFiles.size(); ++pkgIndex)
	{
		std::fstream infile(pkgFiles[pkgIndex], std::ios::in | std::ios::binary);

		if(!infile.is_open())
		{
			std::cerr << "Could not open file " << pkgFiles[pkgIndex] << " skipping..." << std::endl;
			continue;
		}

		std::vector<uint8_t> dataBuf(0x30);

		infile.read((char*)&dataBuf[0], 0x30);

		std::string xorKey = DEFAULT_XOR_KEY;
		size_t headerOffset = 0;

		if(gameGeneration >= GG_WRC10)
		{
			XorData(xorKey, dataBuf);
		}

		if(*(uint32_t*)&dataBuf[0] != 'GKPP')
		{
			dataBuf.resize(0x100);

			infile.read((char*)&dataBuf[0x30], 0x100-0x30);

			for(size_t i = 0x30; i < dataBuf.size(); ++i)
			{
				dataBuf[i] ^= xorKey[i%xorKey.size()];
			}

			std::string publicKey =
				"-----BEGIN PUBLIC KEY-----\r\n"
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAohx1scPAXQSAF4E7wuEz\r\n"
				"ehIAiCiU9OMFGvCLoSmtQUOCQDPqY3bykOKBMqGJKQ7yaf55jiJHaW3lCZkWLOBO\r\n"
				"46pAUOtoxVeQ9+4M4BmCUalTwWq/SsCc/JuEl6j+7DK1sGBAcjz/uyxvmVa85TtO\r\n"
				"zDXEc2oDBhoNdg1AcMnwU7PQsdON/qiI7UIZ4JZ7QzoAklvA3GBdT93ln6UVy5U2\r\n"
				"KWj8pCwMcVEJ5UOxdGWCebTvF7yxvPo+6AhkFUyrZ1lOWA6kgu8z3xzdnBet/fzf\r\n"
				"+nHQZ5eT09ackoWjuGe6rFxAcEqVb80KqkPjqTIoKprkegl78yXeewraegjEXzZj\r\n"
				"ywIDAQAB\r\n"
				"-----END PUBLIC KEY-----";

			BIO *bio = BIO_new_mem_buf((void*)publicKey.c_str(), publicKey.size());
			RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
			if(!rsa)
			{
				std::cerr << "Could not decode public key, skipping this package..." << std::endl;
				continue;
			}

			std::vector<uint8_t> decryptedData(0x100);
			int decryptedSize = RSA_public_decrypt(dataBuf.size(), &dataBuf[0], &decryptedData[0], rsa, RSA_PKCS1_PADDING);

			if(decryptedSize < 0)
			{
				std::cerr << "Could not decrypt data, skipping this package..." << std::endl;
				continue;
			}

			RSA_free(rsa);
			BIO_free(bio);

			headerOffset = 0x180; //encrypted xor key + sig

			xorKey = std::string((char*)&decryptedData[0], decryptedSize);

			dataBuf.resize(0x30);

			infile.seekg(headerOffset, std::ios::beg);
			infile.read((char*)&dataBuf[0], 0x30);

			XorData(xorKey, dataBuf);
		}

		PPKGHeader *header = (PPKGHeader*)&dataBuf[0];

		std::vector<uint8_t> fileHeadersBuf(header->fileHeadersSize);
		infile.read((char*)&fileHeadersBuf[0], header->fileHeadersSize);

		if(gameGeneration >= GG_WRC10)
		{
			XorData(xorKey, fileHeadersBuf, headerOffset+0x30);
		}

		std::span<const uint8_t> remainingFileHeadersData = fileHeadersBuf;

		std::vector<FileMetadata> pkgFileMetadata;

		pkgFileMetadata.reserve(header->fileHeadersSize/sizeof(FileMetadata));

		while(remainingFileHeadersData.size() > 0)
		{
			FileMetadata meta = {};

			uint32_t fileNameSize = *(uint32_t*)&remainingFileHeadersData[0];
			remainingFileHeadersData = remainingFileHeadersData.subspan(sizeof(uint32_t));

			meta.fileName = std::string((char*)&remainingFileHeadersData[0], fileNameSize);
			remainingFileHeadersData = remainingFileHeadersData.subspan(fileNameSize);

			//some sort of checksum
			remainingFileHeadersData = remainingFileHeadersData.subspan(4);

			meta.dataOffset = *(uint64_t*)&remainingFileHeadersData[0];
			remainingFileHeadersData = remainingFileHeadersData.subspan(sizeof(uint64_t));

			meta.filetime = *(uint64_t*)&remainingFileHeadersData[0];
			remainingFileHeadersData = remainingFileHeadersData.subspan(sizeof(uint64_t));

			meta.rawDataSize = *(uint64_t*)&remainingFileHeadersData[0];
			remainingFileHeadersData = remainingFileHeadersData.subspan(sizeof(uint64_t));

			meta.uncompressedDataSize = *(uint64_t*)&remainingFileHeadersData[0];
			remainingFileHeadersData = remainingFileHeadersData.subspan(sizeof(uint64_t));

			meta.compressionType = *(FileCompressionType*)&remainingFileHeadersData[0];
			remainingFileHeadersData = remainingFileHeadersData.subspan(sizeof(uint32_t));

			//some sort of checksum and or signature
			switch(gameGeneration)
			{
				case GG_WRC9:
				case GG_WRC10:
				{
					remainingFileHeadersData = remainingFileHeadersData.subspan(0x28);
				}
				break;
				case GG_WRCG:
				{
					remainingFileHeadersData = remainingFileHeadersData.subspan(0x30);
				}
				break;
			}

			pkgFileMetadata.push_back(std::move(meta));
		}

		for(size_t fileIndex = 0; fileIndex < pkgFileMetadata.size(); ++fileIndex)
		{
			FileMetadata &fileMeta = pkgFileMetadata[fileIndex];
			std::cout << pkgIndex << "/" << pkgFiles.size() << " " << fileIndex << "/" << pkgFileMetadata.size() << " " << fileMeta.fileName << std::endl;

			std::filesystem::path outputPath = basePath / fileMeta.fileName;
			std::filesystem::path outpurDir = outputPath.parent_path();

			std::filesystem::create_directories(outpurDir);

			if(fileMeta.compressionType == FCT_Unk1)
			{
				std::cerr << "File is compressed with unimplemented compression type, skipping..." << std::endl;
				continue;
			}

			char sanityMagic[4];

			infile.seekg(fileMeta.dataOffset, std::ios::beg);

			infile.read(sanityMagic, sizeof(sanityMagic));

			if(memcmp(sanityMagic, "PKGB", 4) != 0)
			{
				std::cerr << "File begin magic sanity check failed, skipping..." << std::endl;
				continue;
			}

			uint8_t *rawDataBuf = new uint8_t[fileMeta.rawDataSize];
			infile.read((char*)rawDataBuf, fileMeta.rawDataSize);

			infile.read(sanityMagic, sizeof(sanityMagic));

			if(memcmp(sanityMagic, "PKGE", 4) != 0)
			{
				std::cerr << "File end magic sanity check failed, skipping..." << std::endl;
				continue;
			}

			uint8_t *decompressedDataBuf = new uint8_t[fileMeta.uncompressedDataSize];

			switch(fileMeta.compressionType)
			{
				case FCT_None:
				{
					if(fileMeta.rawDataSize != fileMeta.uncompressedDataSize)
					{
						__debugbreak();
					}

					memcpy(decompressedDataBuf, rawDataBuf, fileMeta.uncompressedDataSize);
				}
				break;
				case FCT_LZ4F:
				{
					LZ4F_dctx *dctxPtr = nullptr;

					LZ4F_createDecompressionContext(&dctxPtr, LZ4F_VERSION);

					size_t decompressedSize = fileMeta.uncompressedDataSize;
					size_t compressedSize = fileMeta.rawDataSize;

					LZ4F_decompress(dctxPtr, decompressedDataBuf, &decompressedSize, rawDataBuf, &compressedSize, nullptr);

					LZ4F_freeDecompressionContext(dctxPtr);

					if(decompressedSize != fileMeta.uncompressedDataSize)
					{
						__debugbreak();
					}
				}
				break;
			}

			delete [] rawDataBuf;

			std::fstream outfile(outputPath, std::ios::out | std::ios::binary);
			outfile.write((char*)decompressedDataBuf, fileMeta.uncompressedDataSize);
			outfile.close();

			delete [] decompressedDataBuf;
		}
	}

	const auto settingsFilePath = basePath / "COMMON" / "SETTINGS" / "SETTINGS.CFG";

	if(!std::filesystem::exists(settingsFilePath))
	{
		std::cout << "Decrypting settings file..." << std::endl;

		const auto encryptedSettingsFilePath = basePath / "COMMON" / "SETTINGS" / "DUMMYS.DAT";

		if(std::filesystem::exists(encryptedSettingsFilePath))
		{
			std::fstream infile(encryptedSettingsFilePath, std::ios::in | std::ios::binary);
			if(infile.is_open())
			{
				infile.seekg(0, std::ios::end);
				const size_t fileSize = infile.tellg();
				infile.seekg(0, std::ios::beg);

				uint8_t *fileData = new uint8_t[fileSize];
				infile.read((char*)fileData, fileSize);
				infile.close();

				XorData(DEFAULT_XOR_KEY, std::span<uint8_t>(fileData, fileSize));

				if(gameGeneration == GG_WRC10)
				{
					std::cout << "For some reason the last 5 bytes of the WRC10 settings file use a different key, attempting to fix..." << std::endl;

					//Revert default xor
					XorData(DEFAULT_XOR_KEY, std::span<uint8_t>(fileData+fileSize-5, 5), fileSize-5);

					XorData("NPpYg", std::span<uint8_t>(fileData+fileSize-5, 5));
				}

				std::fstream outfile(settingsFilePath, std::ios::out | std::ios::binary);
				outfile.write((char*)fileData, fileSize);

				delete [] fileData;
			}
			else
			{
				std::cerr << "Failed to open encrypted settings file, skipping..." << std::endl;
			}
		}
		else
		{
			std::cerr << "Encrypted settings file was missing, skipping..." << std::endl;
		}
	}
}