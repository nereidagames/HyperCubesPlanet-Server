--- START OF FILE scene.txt ---

import * as THREE from 'three';

const API_BASE_URL = 'https://hypercubes-nexus-server.onrender.com';

export class SceneManager {
  constructor(scene, loadingManager) {
    this.scene = scene;
    this.loadingManager = loadingManager;
    this.collidableObjects = []; // Tablica obiektów, z którymi gracz się zderza
    
    // Ustawienia mapy
    this.MAP_SIZE = 64;
    this.BLOCK_SIZE = 1;
    this.BARRIER_HEIGHT = 100; 
    this.BARRIER_THICKNESS = 1;
    this.FLOOR_TOP_Y = 0.1; // Ważne dla fizyki
    
    this.isInitialized = false;
    
    this.textureLoader = new THREE.TextureLoader(this.loadingManager);
    this.materials = {};
    
    // Współdzielona geometria (Optymalizacja RAM)
    this.sharedCollisionGeometry = new THREE.BoxGeometry(1, 1, 1);
    
    this.maxAnisotropy = 4; 
  }
  
  async initialize() {
    if (this.isInitialized) return;

    this.maxAnisotropy = 16;

    this.setupLighting();
    this.setupFog();

    // Próba załadowania Nexusa z bazy danych
    const nexusLoaded = await this.loadNexusFromDB();

    if (!nexusLoaded) {
        console.log("Brak mapy Nexusa w bazie, generowanie domyślnej...");
        this.createCheckerboardFloor();
    }

    this.createBarrierBlocks();

    this.isInitialized = true;
    console.log("SceneManager zainicjalizowany (Tryb: Instanced Rendering + Anisotropy).");
  }
  
  setupLighting() {
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.7); 
    this.scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(30, 60, 40); 
    directionalLight.castShadow = true;
    
    directionalLight.shadow.mapSize.width = 1024;
    directionalLight.shadow.mapSize.height = 1024;
    directionalLight.shadow.camera.near = 0.5;
    directionalLight.shadow.camera.far = 100;
    
    const shadowSize = 40;
    directionalLight.shadow.camera.left = -shadowSize;
    directionalLight.shadow.camera.right = shadowSize;
    directionalLight.shadow.camera.top = shadowSize;
    directionalLight.shadow.camera.bottom = -shadowSize;
    directionalLight.shadow.bias = -0.0005;
    
    this.scene.add(directionalLight);
  }
  
  setupFog() {
    this.scene.fog = new THREE.Fog(0x87CEEB, 15, 90);
  }

  async loadNexusFromDB() {
      try {
          const response = await fetch(`${API_BASE_URL}/api/nexus`);
          if (!response.ok) return false; 

          const blocksData = await response.json();
          if (!Array.isArray(blocksData) || blocksData.length === 0) return false;

          console.log(`Wczytywanie Nexusa: ${blocksData.length} bloków.`);

          const blocksByTexture = {};

          blocksData.forEach(block => {
              if (!blocksByTexture[block.texturePath]) {
                  blocksByTexture[block.texturePath] = [];
              }
              blocksByTexture[block.texturePath].push(block);
          });

          const dummy = new THREE.Object3D();

          for (const [texturePath, blocks] of Object.entries(blocksByTexture)) {
              
              let material = this.materials[texturePath];
              if (!material) {
                  const texture = this.textureLoader.load(texturePath);
                  texture.magFilter = THREE.NearestFilter;
                  texture.minFilter = THREE.NearestMipmapLinearFilter;
                  texture.anisotropy = this.maxAnisotropy;
                  texture.wrapS = THREE.RepeatWrapping;
                  texture.wrapT = THREE.RepeatWrapping;

                  material = new THREE.MeshLambertMaterial({ map: texture });
                  this.materials[texturePath] = material;
              }

              const instancedMesh = new THREE.InstancedMesh(this.sharedCollisionGeometry, material, blocks.length);
              instancedMesh.castShadow = true;
              instancedMesh.receiveShadow = true;

              blocks.forEach((block, index) => {
                  dummy.position.set(block.x, block.y, block.z);
                  dummy.updateMatrix();
                  instancedMesh.setMatrixAt(index, dummy.matrix);

                  const collisionMesh = new THREE.Mesh(this.sharedCollisionGeometry, new THREE.MeshBasicMaterial());
                  collisionMesh.position.set(block.x, block.y, block.z);
                  collisionMesh.visible = false;
                  
                  this.scene.add(collisionMesh);
                  this.collidableObjects.push(collisionMesh);
              });

              instancedMesh.instanceMatrix.needsUpdate = true;
              this.scene.add(instancedMesh);
          }

          const floorGeo = new THREE.PlaneGeometry(300, 300);
          floorGeo.rotateX(-Math.PI / 2);
          const floorMat = new THREE.MeshBasicMaterial({ visible: false });
          const invisibleFloor = new THREE.Mesh(floorGeo, floorMat);
          invisibleFloor.position.y = -0.5;
          this.scene.add(invisibleFloor);
          this.collidableObjects.push(invisibleFloor);

          return true;
      } catch (error) {
          console.error("Błąd ładowania Nexusa:", error);
          return false;
      }
  }
  
  createCheckerboardFloor() {
    const floorSize = this.MAP_SIZE;
    const floorGeometry = new THREE.PlaneGeometry(floorSize, floorSize);
    floorGeometry.rotateX(-Math.PI / 2);

    const canvas = document.createElement('canvas');
    canvas.width = 2;
    canvas.height = 2;
    const context = canvas.getContext('2d');
    context.fillStyle = '#c0c0c0';
    context.fillRect(0, 0, 2, 2);
    context.fillStyle = '#a0a0a0';
    context.fillRect(0, 0, 1, 1);
    context.fillRect(1, 1, 1, 1);
    
    const texture = new THREE.CanvasTexture(canvas);
    texture.magFilter = THREE.NearestFilter;
    texture.minFilter = THREE.NearestMipmapLinearFilter;
    texture.anisotropy = this.maxAnisotropy;
    texture.repeat.set(floorSize / 2, floorSize / 2);
    texture.wrapS = THREE.RepeatWrapping;
    texture.wrapT = THREE.RepeatWrapping;

    const floorMaterial = new THREE.MeshLambertMaterial({ map: texture });
    const floorMesh = new THREE.Mesh(floorGeometry, floorMaterial);
    floorMesh.receiveShadow = true;
    floorMesh.position.y = -0.5;
    
    this.scene.add(floorMesh);
    this.collidableObjects.push(floorMesh);

    const borderGeometry = new THREE.BoxGeometry(this.MAP_SIZE, 1, this.MAP_SIZE);
    const edges = new THREE.EdgesGeometry(borderGeometry);
    const lineMaterial = new THREE.LineBasicMaterial({ color: 0x8A2BE2, linewidth: 2 });
    const line = new THREE.LineSegments(edges, lineMaterial);
    line.position.y = -0.5;
    this.scene.add(line);
  }
  
  createBarrierBlocks() {
    const halfMapSize = this.MAP_SIZE / 2;
    const barrierY = this.BARRIER_HEIGHT / 2; 
    const barrierMaterial = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false });
    const thickness = this.BARRIER_THICKNESS;

    const wallZ1 = new THREE.Mesh(new THREE.BoxGeometry(this.MAP_SIZE, this.BARRIER_HEIGHT, thickness), barrierMaterial);
    wallZ1.position.set(0, barrierY, halfMapSize);
    this.scene.add(wallZ1);
    this.collidableObjects.push(wallZ1);

    const wallZ2 = new THREE.Mesh(new THREE.BoxGeometry(this.MAP_SIZE, this.BARRIER_HEIGHT, thickness), barrierMaterial);
    wallZ2.position.set(0, barrierY, -halfMapSize);
    this.scene.add(wallZ2);
    this.collidableObjects.push(wallZ2);
    
    const wallX1 = new THREE.Mesh(new THREE.BoxGeometry(thickness, this.BARRIER_HEIGHT, this.MAP_SIZE), barrierMaterial);
    wallX1.position.set(halfMapSize, barrierY, 0);
    this.scene.add(wallX1);
    this.collidableObjects.push(wallX1);
    
    const wallX2 = new THREE.Mesh(new THREE.BoxGeometry(thickness, this.BARRIER_HEIGHT, this.MAP_SIZE), barrierMaterial);
    wallX2.position.set(-halfMapSize, barrierY, 0);
    this.scene.add(wallX2);
    this.collidableObjects.push(wallX2);
  }

  getSafeY(targetX, targetZ) {
      let highestY = -100;
      const checkRadius = 0.8; 

      for (const obj of this.collidableObjects) {
          if (obj.geometry && obj.geometry.type === 'BoxGeometry') {
              if (obj.visible === false) { 
                  const dx = Math.abs(obj.position.x - targetX);
                  const dz = Math.abs(obj.position.z - targetZ);
                  
                  if (dx < checkRadius && dz < checkRadius) {
                      if (obj.position.y > highestY) {
                          highestY = obj.position.y;
                      }
                  }
              }
          }
      }

      if (highestY === -100) return 1.0;
      
      return highestY + 0.5;
  }
}
