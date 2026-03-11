import { RecursiveCharacterTextSplitter } from '@langchain/textsplitters';
import { HuggingFaceTransformersEmbeddings } from '@langchain/community/embeddings/huggingface_transformers';
import { Chroma } from '@langchain/community/vectorstores/chroma';
import { Document } from '@langchain/core/documents';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dataDir = path.join(__dirname, '../data');
const embeddings = new HuggingFaceTransformersEmbeddings({
  modelName: 'Xenova/all-MiniLM-L6-v2',
});

let vectorStore: Chroma | null = null;

export async function initializeVectorStore() {
  if (vectorStore) return vectorStore;

  try {
    vectorStore = await Chroma.fromExistingCollection(
      embeddings,
      { collectionName: 'adansonia' }
    );
    console.log('✅ Loaded existing vector store');
  } catch (e) {
    console.log('🔄 Building vector store from data files...', e.message);
    vectorStore = await buildVectorStore();
  }
  return vectorStore;
}

async function buildVectorStore() {
  const documents: Document[] = [];

  const files = ['staff.json', 'capabilities.json', 'insights.json', 'case-studies.json', 'testimonials.json'];
  for (const file of files) {
    const filePath = path.join(dataDir, file);
    if (!fs.existsSync(filePath)) {
      console.log(`⚠️  File ${file} not found, skipping.`);
      continue;
    }
    try {
      const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      for (const item of content) {
        let text = '';
        if (file === 'staff.json') {
          text = `Name: ${item.name}\nRole: ${item.role}\nBio: ${item.bio || ''}`;
        } else if (file === 'capabilities.json') {
          text = `Practice Area: ${item.title}\nDescription: ${item.description}`;
        } else if (file === 'insights.json') {
          text = `Title: ${item.title}\nDate: ${item.published_date}\nContent: ${item.content}`;
        } else if (file === 'case-studies.json') {
          text = `Case Study: ${item.title}\nPractice Area: ${item.practiceArea}\nDescription: ${item.description}\nOutcome: ${item.outcome}`;
        } else if (file === 'testimonials.json') {
          text = `Testimonial by ${item.name}\nRole: ${item.role}\nQuote: ${item.quote}`;
        }
        if (text) {
          documents.push(new Document({
            pageContent: text,
            metadata: { source: file, id: item.id, title: item.title || item.name }
          }));
        }
      }
    } catch (e) {
      console.error(`❌ Error reading ${file}:`, e.message);
    }
  }

  console.log(`📄 Total documents before splitting: ${documents.length}`);

  const splitter = new RecursiveCharacterTextSplitter({ chunkSize: 500, chunkOverlap: 50 });
  const chunks = await splitter.splitDocuments(documents);
  console.log(`✂️ Split into ${chunks.length} chunks`);

  try {
    const store = await Chroma.fromDocuments(
      chunks,
      embeddings,
      { collectionName: 'adansonia', path: path.join(__dirname, '../chroma_db') }
    );
    console.log(`✅ Vector store built successfully`);
    return store;
  } catch (e) {
    console.error('❌ Failed to build vector store:', e);
    throw e;
  }
}

export async function searchRelevantContext(query: string, k: number = 3): Promise<string> {
  const store = await initializeVectorStore();
  const results = await store.similaritySearch(query, k);
  return results.map(doc => doc.pageContent).join('\n\n---\n\n');
}